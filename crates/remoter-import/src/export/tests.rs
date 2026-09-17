//! Tests for the exporters.
//!
//! The ones that matter most run an export back through this crate's own
//! importer and compare what the connections would actually do — host, port,
//! account, route — before and after. A writer that produces a plausible file
//! the reader then misreads passes every test that only looks at the text.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::too_many_lines,
    reason = "test code, per docs/development/coding-standards.md"
)]

use std::collections::BTreeMap;

use proptest::prelude::*;
use remoter_core::{
    ConnectionProps, CredentialProps, CredentialRef, FolderProps, GatewayChain, GatewayHop,
    Inherited, KeyFormat, Node, NodeId, NodeKind, SecretKind, Tag, Tree,
};

use super::*;
use crate::{ImportPreview, Limits, SourceFormat};

/// The sealed bytes every secret in these trees holds. Searched for in every
/// export: none may carry them, in any encoding.
const SEALED: u8 = 0x5a;

const NOW: i64 = 1_760_000_000_000;

// ================================================================= fixture

/// Builds trees node by node, in display order.
#[derive(Default)]
struct Build {
    nodes: Vec<Node>,
}

impl Build {
    fn add(&mut self, parent: Option<NodeId>, name: &str, kind: NodeKind) -> NodeId {
        let mut node = Node::with_id(NodeId::new(), kind, name, NOW);
        node.parent_id = parent;
        node.sort_order = i64::try_from(self.nodes.len()).unwrap();
        let id = node.id;
        self.nodes.push(node);
        id
    }

    fn folder(&mut self, parent: Option<NodeId>, name: &str) -> NodeId {
        self.add(parent, name, NodeKind::folder())
    }

    fn connection(
        &mut self,
        parent: Option<NodeId>,
        name: &str,
        protocol: &str,
        host: &str,
    ) -> NodeId {
        let props = ConnectionProps::new(protocol, host).unwrap();
        self.add(parent, name, NodeKind::Connection(props))
    }

    fn get(&mut self, id: NodeId) -> &mut Node {
        self.nodes.iter_mut().find(|node| node.id == id).unwrap()
    }

    fn connection_mut(&mut self, id: NodeId) -> &mut ConnectionProps {
        match &mut self.get(id).kind {
            NodeKind::Connection(props) => props,
            _ => panic!("not a connection"),
        }
    }

    fn folder_mut(&mut self, id: NodeId) -> &mut FolderProps {
        match &mut self.get(id).kind {
            NodeKind::Folder(props) => props,
            _ => panic!("not a folder"),
        }
    }

    fn tree(self) -> Tree {
        let tree = Tree::from_nodes(self.nodes).unwrap();
        assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        tree
    }
}

fn password() -> SecretKind {
    SecretKind::Password {
        sealed: vec![SEALED; 40],
    }
}

fn private_key() -> SecretKind {
    SecretKind::PrivateKey {
        sealed_key: vec![SEALED; 64],
        sealed_passphrase: Some(vec![SEALED; 24]),
        format: KeyFormat::OpenSsh,
    }
}

fn hops(ids: &[NodeId]) -> Inherited<GatewayChain> {
    Inherited::Explicit(ids.iter().copied().map(GatewayHop::new).collect())
}

/// An estate with the things a CSV has to flatten: a folder that sets the port
/// and the credential, a shared credential kept in a folder of its own, a
/// two-hop route, an RDP host with a domain account, and names and notes a
/// spreadsheet would mangle.
fn estate() -> (Tree, BTreeMap<&'static str, NodeId>) {
    let mut b = Build::default();
    let mut ids = BTreeMap::new();

    let vault_folder = b.folder(None, "Credentials");
    let mut svc = CredentialProps::new("svc-deploy", password());
    svc.domain = Some("CORP".into());
    let svc = b.add(Some(vault_folder), "svc", NodeKind::Credential(svc));
    let admin = b.add(
        Some(vault_folder),
        "admin key",
        NodeKind::Credential(CredentialProps::new("ops", private_key())),
    );

    let production = b.folder(None, "Production");
    b.folder_mut(production).port = Inherited::Explicit(2222);
    b.folder_mut(production).credential = Inherited::Explicit(CredentialRef::live(svc));
    ids.insert("production", production);

    let web = b.folder(Some(production), "Web tier");
    let web01 = b.connection(Some(web), "web-01", "ssh", "web-01.example.com");
    let formula = b.connection(Some(web), "=HYPERLINK(\"x\")", "ssh", "web-02.example.com");
    {
        let node = b.get(formula);
        node.description =
            "Line one, with a comma\nhost is behind the NAT; \"quoted\"\n-dash".into();
        node.tags = vec![Tag::new("prod").unwrap(), Tag::new("web").unwrap()];
    }
    ids.insert("web-01", web01);

    let bastion = b.connection(Some(production), "bastion", "ssh", "bastion.example.com");
    b.connection_mut(bastion).credential = Inherited::Explicit(CredentialRef::live(admin));
    let inner = b.connection(Some(production), "inner-hop", "ssh", "10.0.0.5");
    b.connection_mut(inner).port = Inherited::Default;
    let db = b.connection(Some(production), "db-primary", "ssh", "[2001:db8::10]");
    b.connection_mut(db).gateway = hops(&[bastion, inner]);
    b.connection_mut(web01).gateway = hops(&[bastion]);
    ids.insert("bastion", bastion);
    ids.insert("db-primary", db);

    let windows = b.folder(None, "Windows");
    let rdp = b.connection(Some(windows), "dc-01", "rdp", "dc-01.corp.example");
    b.connection_mut(rdp).credential = Inherited::Explicit(CredentialRef::live(svc));
    ids.insert("dc-01", rdp);

    (b.tree(), ids)
}

/// The preview a file becomes, as the tree committing it would build.
fn tree_of(preview: ImportPreview) -> Tree {
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| {
            let sealed = node.needs_sealing().then(|| vec![0xaa; 48]);
            node.into_node(NOW, sealed).unwrap()
        })
        .collect();
    Tree::from_nodes(nodes).unwrap()
}

/// What a connection would do, flattened: everything a CSV row can say.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Behaviour {
    folder: String,
    protocol: String,
    host: String,
    port: Option<u16>,
    username: Option<String>,
    domain: Option<String>,
    route: Vec<String>,
    description: String,
    tags: Vec<String>,
}

fn behaviour(tree: &Tree) -> BTreeMap<String, Behaviour> {
    tree.nodes()
        .filter(|node| node.kind.as_connection().is_some())
        .map(|node| {
            let effective = tree.effective_connection(node.id).unwrap();
            let credential = effective
                .credential
                .value
                .as_ref()
                .and_then(|reference| tree.get(reference.id()))
                .and_then(|credential| credential.kind.as_credential());
            let mut folder: Vec<String> = tree
                .ancestors(node.id)
                .unwrap()
                .iter()
                .map(|ancestor| ancestor.name.clone())
                .collect();
            folder.reverse();
            (
                node.name.clone(),
                Behaviour {
                    folder: folder.join("/"),
                    protocol: effective.protocol.as_str().to_owned(),
                    host: effective.host.clone(),
                    port: effective.port.value,
                    username: credential.map(|props| props.username.clone()),
                    domain: credential.and_then(|props| props.domain.clone()),
                    route: effective
                        .gateway
                        .value
                        .hops
                        .iter()
                        .map(|hop| tree.get(hop.node.id()).unwrap().name.clone())
                        .collect(),
                    description: node.description.clone(),
                    tags: node
                        .tags
                        .iter()
                        .map(|tag| tag.as_str().to_owned())
                        .collect(),
                },
            )
        })
        .collect()
}

/// A description, through a CSV export and back.
fn csv_description(description: &str) -> String {
    let mut b = Build::default();
    let web = b.connection(None, "web", "ssh", "web.example.com");
    b.get(web).description = description.to_owned();
    let exported = export(&b.tree(), None, ExportFormat::Csv, NOW).unwrap();
    let reimported = tree_of(crate::csv::parse(&exported.bytes, &Limits::new()).unwrap());
    behaviour(&reimported)["web"].description.clone()
}

fn text(exported: &Exported) -> String {
    String::from_utf8(exported.bytes.clone()).unwrap()
}

/// No sealed byte run, as raw bytes or as the decimal list serde would write
/// for a `Vec<u8>`, and no field named after one.
fn assert_no_secret(exported: &Exported) {
    let bytes = &exported.bytes;
    assert!(
        !bytes
            .windows(8)
            .any(|window| window.iter().all(|b| *b == SEALED)),
        "raw sealed bytes in a {:?} export",
        exported.report.format
    );
    let text = String::from_utf8_lossy(bytes);
    let decimal = format!("{SEALED},{SEALED},{SEALED}");
    assert!(!text.contains(&decimal), "sealed bytes as a list: {text}");
    assert!(
        !text.contains("sealed"),
        "a sealed field was serialised: {text}"
    );
}

// ===================================================================== CSV

#[test]
fn a_csv_export_imports_back_as_connections_that_behave_the_same() {
    let (tree, _) = estate();
    let exported = export(&tree, None, ExportFormat::Csv, NOW).unwrap();
    assert_eq!(exported.report.written, 6);
    assert_eq!(exported.report.connections, 6);
    assert_eq!(exported.report.skipped, 0);

    let reimported = tree_of(crate::csv::parse(&exported.bytes, &Limits::new()).unwrap());
    let before = behaviour(&tree);
    let after = behaviour(&reimported);
    assert_eq!(
        before.keys().collect::<Vec<_>>(),
        after.keys().collect::<Vec<_>>()
    );
    for (name, expected) in &before {
        assert_eq!(&after[name], expected, "{name} changed on the way round");
    }
}

#[test]
fn the_csv_is_what_a_spreadsheet_reads_and_not_what_it_runs() {
    let (tree, _) = estate();
    let exported = export(&tree, None, ExportFormat::Csv, NOW).unwrap();
    let text = text(&exported);

    assert!(text.starts_with("\u{feff}name,folder,protocol,host,port,username,domain,password,description,tags,gateway\r\n"));
    assert!(text.contains("\r\n\"'=HYPERLINK(\"\"x\"\")\","), "{text}");
    assert!(
        text.contains("svc-deploy,CORP,,"),
        "the password column stays empty: {text}"
    );
    assert!(text.contains("bastion > inner-hop"), "{text}");
    assert_no_secret(&exported);

    // A description line that reads like an ssh_config directive does not
    // make the file look like one.
    assert_eq!(crate::detect(&exported.bytes), Some(SourceFormat::Csv));
}

#[test]
fn exporting_a_folder_writes_that_folder_and_nothing_above_or_beside_it() {
    let (tree, ids) = estate();
    let exported = export(&tree, Some(ids["production"]), ExportFormat::Csv, NOW).unwrap();
    assert_eq!(exported.report.connections, 5);
    assert_eq!(exported.report.folders, 2);

    let reimported = tree_of(crate::csv::parse(&exported.bytes, &Limits::new()).unwrap());
    let after = behaviour(&reimported);
    assert!(!after.contains_key("dc-01"));
    assert_eq!(after["web-01"].folder, "Production/Web tier");
    // Values set above the root still apply: they are the effective ones.
    assert_eq!(after["web-01"].port, Some(2222));
    assert_eq!(after["web-01"].username.as_deref(), Some("svc-deploy"));
}

#[test]
fn a_route_through_a_name_two_connections_share_is_left_out_and_said_so() {
    let mut b = Build::default();
    let first = b.connection(None, "bastion", "ssh", "a.example.com");
    b.connection(None, "bastion", "ssh", "b.example.com");
    let web = b.connection(None, "web", "ssh", "web.example.com");
    b.connection_mut(web).gateway = hops(&[first]);
    let tree = b.tree();

    let exported = export(&tree, None, ExportFormat::Csv, NOW).unwrap();
    assert!(text(&exported).contains("web,,ssh,web.example.com,22,,,,,,\r\n"));
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::GatewayNotWritten {
                item: "web".into(),
                reason: GatewayProblem::AmbiguousHop,
            })
    );
}

#[test]
fn a_hop_outside_the_export_is_written_by_name_and_flagged() {
    let mut b = Build::default();
    let shared = b.folder(None, "Shared");
    let bastion = b.connection(Some(shared), "bastion", "ssh", "bastion.example.com");
    let team = b.folder(None, "Team");
    let web = b.connection(Some(team), "web", "ssh", "web.example.com");
    b.connection_mut(web).gateway = hops(&[bastion]);
    let tree = b.tree();

    let exported = export(&tree, Some(team), ExportFormat::Csv, NOW).unwrap();
    assert!(
        text(&exported).ends_with(",bastion\r\n"),
        "{}",
        text(&exported)
    );
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::GatewayNotWritten {
                item: "web".into(),
                reason: GatewayProblem::HopOutsideExport,
            })
    );
}

#[test]
fn the_csv_reader_takes_a_route_of_several_hops_and_a_name_with_a_chevron() {
    let file = "name,host,gateway\n\
                a > b,ab.example.com,\n\
                a,a.example.com,\n\
                b,b.example.com,a\n\
                c,c.example.com,a > b\n\
                d,d.example.com,a > b\n\
                e,e.example.com,a > nowhere\n\
                f,f.example.com,f\n";
    let tree = tree_of(crate::csv::parse(file.as_bytes(), &Limits::new()).unwrap());
    let routes = behaviour(&tree);
    assert_eq!(routes["b"].route, ["a"]);
    // The whole cell names a row, so it is that row, not two hops.
    assert_eq!(routes["c"].route, ["a > b"]);
    assert_eq!(routes["d"].route, ["a > b"]);
    assert!(
        routes["e"].route.is_empty(),
        "a route missing a hop is no route"
    );
    assert!(
        routes["f"].route.is_empty(),
        "a connection is not its own jump host"
    );

    let file = "name,host,gateway\na,a.example.com,\nb,b.example.com,\nc,c.example.com, a>b \n";
    let tree = tree_of(crate::csv::parse(file.as_bytes(), &Limits::new()).unwrap());
    assert_eq!(behaviour(&tree)["c"].route, ["a", "b"]);
}

#[test]
fn a_folder_name_with_a_slash_is_flagged_for_the_csv() {
    let mut b = Build::default();
    let folder = b.folder(None, "EU/West");
    b.connection(Some(folder), "web", "ssh", "web.example.com");
    let exported = export(&b.tree(), None, ExportFormat::Csv, NOW).unwrap();
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::FolderNameSplits {
                folder: "EU/West".into()
            })
    );
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    /// Whatever a description holds — delimiters, quotes, newlines, a leading
    /// `=` or apostrophes in front of one — it comes back as it went out, less
    /// the whitespace at its ends that the importer trims from every field.
    #[test]
    fn any_description_survives_the_csv(description in "[ -~\n\t\"',;=+@\u{e7}\u{15f}\u{fc}-]{0,40}") {
        prop_assert_eq!(csv_description(&description), description.trim());
    }

    /// The guard's own corner: apostrophes, formula characters and spaces in
    /// every order, where a guard in the wrong place is undone wrongly.
    #[test]
    fn the_formula_guard_is_undone_exactly(value in "['=+@a \t-]{0,6}") {
        prop_assert_eq!(csv_description(&value), value.trim());
    }
}

// ============================================================ ssh_config

/// An SSH estate: a bastion with a key file, a route through it and through a
/// host outside the export, a name `ssh` could not select, an IPv6 target and
/// timeouts that are not whole seconds.
fn ssh_estate() -> (Tree, BTreeMap<&'static str, NodeId>) {
    let mut b = Build::default();
    let mut ids = BTreeMap::new();

    let keys = b.folder(None, "Keys");
    let key_file = b.add(
        Some(keys),
        "ops key",
        NodeKind::Credential(CredentialProps::new(
            "ops",
            SecretKind::External {
                provider: "openssh-identity-file".into(),
                reference: "~/.ssh/ops key".into(),
            },
        )),
    );
    let deploy = b.add(
        Some(keys),
        "deploy",
        NodeKind::Credential(CredentialProps::new("deploy", password())),
    );

    let elsewhere = b.folder(None, "Elsewhere");
    let outside = b.connection(Some(elsewhere), "edge", "ssh", "edge.example.com");
    b.connection_mut(outside).port = Inherited::Explicit(2200);
    b.connection_mut(outside).credential = Inherited::Explicit(CredentialRef::live(deploy));

    let estate = b.folder(None, "Estate");
    b.folder_mut(estate).keepalive_secs = Inherited::Explicit(30);
    b.folder_mut(estate).connect_timeout_ms = Inherited::Explicit(1500);
    ids.insert("estate", estate);

    let bastion = b.connection(Some(estate), "Bastion", "ssh", "bastion.example.com");
    b.connection_mut(bastion).port = Inherited::Explicit(2222);
    b.connection_mut(bastion).credential = Inherited::Explicit(CredentialRef::live(key_file));
    let web = b.connection(Some(estate), "Web 01", "ssh", "[2001:db8::1]");
    b.connection_mut(web).gateway = hops(&[bastion, outside]);
    b.connection_mut(web).credential = Inherited::Explicit(CredentialRef::live(deploy));
    let rdp = b.connection(Some(estate), "dc-01", "rdp", "dc-01.example.com");
    ids.insert("bastion", bastion);
    ids.insert("web", web);
    ids.insert("rdp", rdp);

    (b.tree(), ids)
}

#[test]
fn an_ssh_config_export_reads_back_as_the_same_routes_to_the_same_hosts() {
    let (tree, ids) = ssh_estate();
    let exported = export(&tree, Some(ids["estate"]), ExportFormat::OpenSshConfig, NOW).unwrap();
    let text = text(&exported);

    assert_eq!(exported.report.written, 2);
    assert_eq!(exported.report.skipped, 1);
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::UnsupportedProtocol {
                item: "dc-01".into(),
                protocol: "rdp".into(),
            })
    );
    assert!(exported.report.notes.contains(&ExportNote::Renamed {
        item: "Web 01".into(),
        written: "web-01".into(),
    }));
    assert!(
        !exported
            .report
            .notes
            .iter()
            .any(|note| matches!(note, ExportNote::Renamed { item, .. } if item == "Bastion")),
        "a name that differs only in case is not a rename"
    );
    assert!(text.contains(
        "Host bastion\n    HostName bastion.example.com\n    Port 2222\n    User ops\n    IdentityFile \"~/.ssh/ops key\"\n    ConnectTimeout 2\n    ServerAliveInterval 30\n"
    ), "{text}");
    assert!(text.contains(
        "Host web-01\n    HostName 2001:db8::1\n    User deploy\n    ProxyJump bastion,deploy@edge.example.com:2200\n"
    ), "{text}");
    assert_no_secret(&exported);
    assert_eq!(
        crate::detect(&exported.bytes),
        Some(SourceFormat::OpenSshConfig)
    );

    let reimported = tree_of(crate::ssh_config::parse(&exported.bytes, &Limits::new()).unwrap());
    let find = |name: &str| {
        reimported
            .nodes()
            .find(|node| node.name == name)
            .map(|node| reimported.effective_connection(node.id).unwrap())
            .unwrap_or_else(|| panic!("no {name} in {text}"))
    };
    let web = find("web-01");
    assert_eq!(web.host, "[2001:db8::1]");
    assert_eq!(web.port.value, Some(22));
    assert_eq!(web.username.value.as_deref(), Some("deploy"));
    assert_eq!(web.keepalive_secs.value, Some(30));
    assert_eq!(
        web.connect_timeout_ms.value,
        Some(2000),
        "rounded up to whole seconds"
    );
    let route: Vec<(String, Option<u16>)> = web
        .gateway
        .value
        .hops
        .iter()
        .map(|hop| {
            let hop = reimported.effective_connection(hop.node.id()).unwrap();
            (hop.host, hop.port.value)
        })
        .collect();
    assert_eq!(
        route,
        [
            ("bastion.example.com".to_owned(), Some(2222)),
            ("edge.example.com".to_owned(), Some(2200)),
        ]
    );

    let bastion = find("bastion");
    let credential = reimported
        .get(bastion.credential.value.unwrap().id())
        .and_then(|node| node.kind.as_credential())
        .unwrap();
    assert_eq!(
        credential.secret,
        SecretKind::External {
            provider: "openssh-identity-file".into(),
            reference: "~/.ssh/ops key".into(),
        }
    );
}

#[test]
fn aliases_are_unique_selectable_patterns() {
    let mut b = Build::default();
    b.connection(None, "Web 01", "ssh", "a.example.com");
    b.connection(None, "web-01", "ssh", "b.example.com");
    b.connection(None, "*prod*, db!", "ssh", "c.example.com");
    b.connection(None, "Üretim sunucusu", "sftp", "d.example.com");
    b.connection(None, "日本", "ssh", "e.example.com");
    let exported = export(&b.tree(), None, ExportFormat::OpenSshConfig, NOW).unwrap();
    let hosts: Vec<&str> = std::str::from_utf8(&exported.bytes)
        .unwrap()
        .lines()
        .filter_map(|line| line.strip_prefix("Host "))
        .collect();
    assert_eq!(
        hosts,
        [
            "web-01",
            "web-01-2",
            "prod-db",
            "uretim-sunucusu",
            "e.example.com"
        ]
    );
}

#[test]
fn an_ssh_route_through_something_that_is_not_ssh_is_not_written() {
    let mut b = Build::default();
    let rdp = b.connection(None, "rdg", "rdp", "rdg.example.com");
    let web = b.connection(None, "web", "ssh", "web.example.com");
    b.connection_mut(web).gateway = hops(&[rdp]);
    let exported = export(&b.tree(), None, ExportFormat::OpenSshConfig, NOW).unwrap();
    assert!(!text(&exported).contains("ProxyJump"));
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::GatewayNotWritten {
                item: "web".into(),
                reason: GatewayProblem::HopNotSsh,
            })
    );
}

#[test]
fn a_user_no_ssh_config_can_hold_is_left_out_and_said_so() {
    let mut b = Build::default();
    let credential = b.add(
        None,
        "odd",
        NodeKind::Credential(CredentialProps::new("say \"hi\"", password())),
    );
    let web = b.connection(None, "web", "ssh", "web.example.com");
    b.connection_mut(web).credential = Inherited::Explicit(CredentialRef::live(credential));
    let exported = export(&b.tree(), None, ExportFormat::OpenSshConfig, NOW).unwrap();
    assert!(!text(&exported).contains("User"));
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::ValueNotWritten {
                item: "web".into(),
                field: "user".into(),
            })
    );
}

// ==================================================================== JSON

#[test]
fn the_json_is_the_tree_as_stored_without_a_secret_in_it() {
    let (tree, ids) = estate();
    let exported = export(&tree, None, ExportFormat::Json, NOW).unwrap();
    assert_no_secret(&exported);
    let document: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();

    assert_eq!(document["format"], "remoter-tree");
    assert_eq!(document["version"], 1);
    assert_eq!(document["secrets"], "excluded");
    assert_eq!(document["exported_at"], NOW);
    assert!(document["root"].is_null());
    let nodes = document["nodes"].as_array().unwrap();
    assert_eq!(nodes.len(), tree.len());
    assert_eq!(exported.report.written, tree.len());
    assert!(document["outside"].as_array().unwrap().is_empty());

    // Parents before children, in display order.
    let names: Vec<&str> = nodes
        .iter()
        .map(|node| node["name"].as_str().unwrap())
        .collect();
    assert_eq!(
        &names[..4],
        ["Credentials", "svc", "admin key", "Production"]
    );

    let by_name = |name: &str| nodes.iter().find(|node| node["name"] == name).unwrap();
    // Inheritance as the vault stores it, not flattened.
    assert_eq!(
        by_name("Production")["kind"]["Folder"]["port"],
        serde_json::json!({"Explicit": 2222})
    );
    assert_eq!(by_name("web-01")["kind"]["Connection"]["port"], "Inherit");
    assert_eq!(
        by_name("inner-hop")["kind"]["Connection"]["port"],
        "Default"
    );
    let route = &by_name("db-primary")["kind"]["Connection"]["gateway"]["Explicit"]["hops"];
    assert_eq!(route[0]["node"]["Live"], serde_json::json!(ids["bastion"]));
    assert_eq!(route[1]["node"]["Live"], by_name("inner-hop")["id"]);

    // A credential says what it holds, and nothing of it.
    assert_eq!(by_name("svc")["kind"]["Credential"]["secret"], "Password");
    assert_eq!(by_name("svc")["kind"]["Credential"]["domain"], "CORP");
    assert_eq!(
        by_name("admin key")["kind"]["Credential"]["secret"],
        serde_json::json!({"PrivateKey": {"format": "OpenSsh", "has_passphrase": true}})
    );
}

#[test]
fn a_json_export_of_a_folder_names_what_it_points_at_outside_itself() {
    let (tree, ids) = estate();
    let exported = export(&tree, Some(ids["production"]), ExportFormat::Json, NOW).unwrap();
    let document: serde_json::Value = serde_json::from_slice(&exported.bytes).unwrap();

    assert_eq!(document["root"], serde_json::json!(ids["production"]));
    let nodes = document["nodes"].as_array().unwrap();
    assert!(
        nodes[0]["parent_id"].is_null(),
        "the root has no parent in the file"
    );
    let outside: Vec<&str> = document["outside"]
        .as_array()
        .unwrap()
        .iter()
        .map(|node| node["name"].as_str().unwrap())
        .collect();
    assert_eq!(outside.len(), 2, "{outside:?}");
    assert!(outside.contains(&"svc") && outside.contains(&"admin key"));
    assert!(
        exported
            .report
            .notes
            .contains(&ExportNote::OutsideReference {
                item: "Production".into(),
                target: "svc".into(),
            })
    );
}

// ================================================================ archive

#[test]
fn an_archive_of_a_folder_brings_what_the_folder_depends_on() {
    let mut b = Build::default();
    let shared = b.folder(None, "Shared");
    let svc = b.add(
        Some(shared),
        "svc",
        NodeKind::Credential(CredentialProps::new("svc-deploy", password())),
    );
    let hop_key = b.add(
        Some(shared),
        "hop key",
        NodeKind::Credential(CredentialProps::new("ops", private_key())),
    );
    let bastion = b.connection(Some(shared), "bastion", "ssh", "bastion.example.com");
    b.connection_mut(bastion).credential = Inherited::Explicit(CredentialRef::live(hop_key));
    b.connection(Some(shared), "unrelated", "ssh", "unrelated.example.com");

    let estate = b.folder(None, "Estate");
    b.folder_mut(estate).port = Inherited::Explicit(2222);
    let team = b.folder(Some(estate), "Team");
    b.folder_mut(team).credential = Inherited::Explicit(CredentialRef::live(svc));
    let web = b.connection(Some(team), "web", "ssh", "web.example.com");
    b.connection_mut(web).gateway = hops(&[bastion]);
    let tree = b.tree();

    let selection = archive_selection(&tree, Some(team)).unwrap();
    let names: Vec<&str> = selection
        .nodes
        .iter()
        .map(|node| node.name.as_str())
        .collect();
    // The folder's own credential is found first, then the route of the
    // connection under it, then what that route needs in turn.
    assert_eq!(names, ["Team", "web", "svc", "bastion", "hop key"]);
    assert_eq!(selection.dependencies, ["svc", "bastion", "hop key"]);

    let by_name = |name: &str| {
        selection
            .nodes
            .iter()
            .find(|node| node.name == name)
            .unwrap()
    };
    // The root keeps the port its own folder gave it, and loses the parent it
    // will not have.
    assert_eq!(by_name("Team").parent_id, None);
    assert_eq!(
        by_name("Team").kind.as_folder().unwrap().port,
        Inherited::Explicit(2222)
    );
    assert_eq!(by_name("web").parent_id, Some(team));
    for dependency in ["bastion", "svc", "hop key"] {
        assert_eq!(by_name(dependency).parent_id, None, "{dependency}");
    }

    // Put down on their own, the nodes resolve as they did in place.
    let alone = Tree::from_nodes(selection.nodes.clone()).unwrap();
    assert!(
        alone.validate_all().is_empty(),
        "{:?}",
        alone.validate_all()
    );
    let before = tree.effective_connection(web).unwrap();
    let after = alone.effective_connection(web).unwrap();
    assert_eq!(after.port.value, before.port.value);
    assert_eq!(after.credential.value, before.credential.value);
    assert_eq!(after.gateway.value, before.gateway.value);
    assert_eq!(
        alone
            .effective_connection(bastion)
            .unwrap()
            .credential
            .value,
        Some(CredentialRef::live(hop_key))
    );
}

#[test]
fn an_archive_of_one_connection_brings_the_credential_it_owns() {
    let mut b = Build::default();
    let folder = b.folder(None, "Estate");
    let web = b.connection(Some(folder), "web", "ssh", "web.example.com");
    let mut own = CredentialProps::attached(web, "root", password());
    own.domain = None;
    let own = b.add(Some(folder), "web", NodeKind::Credential(own));
    b.connection_mut(web).credential = Inherited::Explicit(CredentialRef::live(own));
    let tree = b.tree();

    let selection = archive_selection(&tree, Some(web)).unwrap();
    assert_eq!(selection.nodes.len(), 2);
    assert_eq!(selection.nodes[1].id, own);
    assert_eq!(
        selection.nodes[1].kind.as_credential().unwrap().attached_to,
        Some(web),
        "it still belongs to the connection it came with"
    );
    assert!(
        Tree::from_nodes(selection.nodes)
            .unwrap()
            .validate_all()
            .is_empty()
    );
}

#[test]
fn an_archive_of_the_vault_is_every_live_node_and_nothing_pulled() {
    let (tree, _) = estate();
    let selection = archive_selection(&tree, None).unwrap();
    assert_eq!(selection.nodes.len(), tree.len());
    assert!(selection.dependencies.is_empty());
    let roots: Vec<&str> = selection
        .nodes
        .iter()
        .filter(|node| node.parent_id.is_none())
        .map(|node| node.name.as_str())
        .collect();
    assert_eq!(roots, ["Credentials", "Production", "Windows"]);
}

// ============================================================ everything

#[test]
fn a_root_that_is_not_there_is_refused_in_every_format() {
    let (tree, _) = estate();
    let missing = NodeId::new();
    for format in ExportFormat::ALL {
        assert!(matches!(
            export(&tree, Some(missing), *format, NOW),
            Err(ExportError::Tree(CoreError::NodeNotFound(id))) if id == missing
        ));
    }
}

#[test]
fn deleted_nodes_are_never_written() {
    let mut b = Build::default();
    let gone = b.connection(None, "decommissioned", "ssh", "old.example.com");
    b.get(gone).deleted_at = Some(NOW);
    b.connection(None, "live", "ssh", "new.example.com");
    let tree = Tree::from_nodes(b.nodes).unwrap();
    for format in ExportFormat::ALL {
        let exported = export(&tree, None, *format, NOW).unwrap();
        assert!(!text(&exported).contains("decommissioned"), "{format:?}");
        assert!(matches!(
            export(&tree, Some(gone), *format, NOW),
            Err(ExportError::Tree(_))
        ));
    }
}

#[test]
fn the_notes_stop_growing_at_the_ceiling_and_keep_counting() {
    let mut b = Build::default();
    for index in 0..(MAX_NOTES + 7) {
        b.connection(None, &format!("rdp-{index}"), "rdp", "rdp.example.com");
    }
    let exported = export(&b.tree(), None, ExportFormat::OpenSshConfig, NOW).unwrap();
    assert_eq!(exported.report.notes.len(), MAX_NOTES);
    assert_eq!(exported.report.notes_dropped, 7);
    assert_eq!(exported.report.skipped, MAX_NOTES + 7);
}

#[test]
fn format_names_round_trip() {
    for format in ExportFormat::ALL {
        assert_eq!(ExportFormat::parse(format.as_str()), Some(*format));
    }
    assert_eq!(ExportFormat::parse("xlsx"), None);
}
