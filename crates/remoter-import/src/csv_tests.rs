//! Tests for the CSV importer.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use remoter_core::{Node, Tree};

use super::*;
use crate::preview::PreviewKind as Kind;

const INVENTORY: &str = "\
name,folder,protocol,host,port,username,domain,password,description,tags,gateway
bastion,Datacentre EU-West,ssh,bastion.eu.acme.internal,2222,svc-deploy,,hunter2,Jump host,production;linux,
web-01,Datacentre EU-West/Web tier,ssh,web-01.eu.acme.internal,,svc-deploy,,hunter2,,production,bastion
web-02,Datacentre EU-West/Web tier,ssh,web-02.eu.acme.internal,,svc-deploy,,hunter2,,production,bastion
ctso-dc01,Customer sites/Contoso,rdp,10.4.0.11,3389,admin,CONTOSO,s3cret,Domain controller,,
";

fn preview_of(text: &str) -> ImportPreview {
    parse(text.as_bytes(), &Limits::new()).unwrap()
}

/// The records the file is split into are a copy of every field in it, the
/// cleartext `password` column included, and they outlive the mapping that
/// reads them. Asserted as a type rather than as a value because the guarantee
/// *is* the type: nothing else makes the buffer wipe when it goes, and a
/// refactor that returned a plain `Vec` would stop compiling here rather than
/// quietly start handing the file back to the allocator.
#[test]
fn the_records_a_file_is_split_into_wipe_themselves() {
    const fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>(_: &T) {}
    let records = read(INVENTORY, &Limits::new()).unwrap();
    wiped_on_drop(&records);
    assert_eq!(records.len(), 5);
}

fn refusal(text: &str) -> ImportError {
    let Err(err) = parse(text.as_bytes(), &Limits::new()) else {
        panic!("expected a refusal");
    };
    err
}

fn find<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewNode {
    preview
        .nodes()
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name}"))
}

fn connection<'a>(preview: &'a ImportPreview, name: &str) -> &'a ConnectionProps {
    let Kind::Connection(props) = &find(preview, name).kind else {
        panic!("{name} is not a connection");
    };
    props
}

#[test]
fn the_documented_columns_map_onto_the_domain_model() {
    let preview = preview_of(INVENTORY);
    assert_eq!(preview.report().counts().connections, 4);

    let bastion = connection(&preview, "bastion");
    assert_eq!(bastion.protocol.as_str(), "ssh");
    assert_eq!(bastion.host, "bastion.eu.acme.internal");
    assert_eq!(bastion.port, Inherited::Explicit(2222));

    let node = find(&preview, "bastion");
    assert_eq!(node.description, "Jump host");
    assert_eq!(
        node.tags.iter().map(Tag::as_str).collect::<Vec<_>>(),
        ["production", "linux"]
    );

    // A blank port is left inherited rather than guessed at.
    assert_eq!(connection(&preview, "web-01").port, Inherited::Inherit);
}

#[test]
fn a_folder_path_becomes_a_folder_tree_created_once() {
    let preview = preview_of(INVENTORY);
    let datacentre = find(&preview, "Datacentre EU-West");
    let web_tier = find(&preview, "Web tier");
    assert_eq!(datacentre.parent_id, None);
    assert_eq!(web_tier.parent_id, Some(datacentre.id));
    assert_eq!(find(&preview, "web-01").parent_id, Some(web_tier.id));
    assert_eq!(find(&preview, "web-02").parent_id, Some(web_tier.id));
    assert_eq!(find(&preview, "bastion").parent_id, Some(datacentre.id));

    // Three rows named the same two folders; each exists once.
    assert_eq!(
        preview
            .nodes()
            .iter()
            .filter(|node| node.name == "Web tier")
            .count(),
        1
    );
}

#[test]
fn one_account_across_three_rows_becomes_one_credential() {
    let preview = preview_of(INVENTORY);
    assert_eq!(preview.report().counts().credentials, 2);
    assert_eq!(preview.report().counts().secrets, 2);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::CredentialsDeduplicated {
                credentials: 2,
                connections: 4
            })
    );

    let Kind::Credential(credential) = &find(&preview, "svc-deploy").kind else {
        panic!("svc-deploy must be a credential");
    };
    assert_eq!(
        credential.secret,
        PreviewSecret::Password(ImportedSecret::from("hunter2"))
    );
    assert_eq!(
        credential
            .allowed_protocols
            .iter()
            .map(ProtocolId::as_str)
            .collect::<Vec<_>>(),
        ["ssh"]
    );
}

#[test]
fn a_gateway_column_naming_another_row_becomes_a_chain() {
    let preview = preview_of(INVENTORY);
    let bastion = find(&preview, "bastion").id;
    let Inherited::Explicit(chain) = &connection(&preview, "web-01").gateway else {
        panic!("web-01 must have a gateway chain");
    };
    assert_eq!(chain.hops.len(), 1);
    assert_eq!(chain.hops[0].node.id(), bastion);
}

#[test]
fn a_gateway_naming_nothing_is_preserved_and_flagged() {
    let preview = preview_of("name,host,gateway\na,a.example.com,nowhere\n");
    assert_eq!(connection(&preview, "a").gateway, Inherited::Inherit);
    assert_eq!(
        find(&preview, "a")
            .custom_fields
            .get("csv.gateway")
            .map(String::as_str),
        Some("nowhere")
    );
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::GatewayUnresolved {
                item: "a".to_owned(),
                target: "nowhere".to_owned()
            })
    );
}

#[test]
fn column_order_does_not_matter_and_optional_columns_may_be_absent() {
    let preview = preview_of("host,name\nweb-01.example.com,web-01\n");
    assert_eq!(connection(&preview, "web-01").host, "web-01.example.com");
    // The default protocol is the one the column set documents.
    assert_eq!(connection(&preview, "web-01").protocol.as_str(), "ssh");
    assert_eq!(connection(&preview, "web-01").port, Inherited::Inherit);
    assert_eq!(preview.report().counts().credentials, 0);
}

#[test]
fn a_required_column_that_is_missing_is_named() {
    assert_eq!(
        refusal("name,protocol\na,ssh\n"),
        ImportError::MissingColumn { column: "host" }
    );
    assert_eq!(
        refusal("host,protocol\na.example.com,ssh\n"),
        ImportError::MissingColumn { column: "name" }
    );
    assert_eq!(
        refusal(""),
        ImportError::WrongFormat {
            expected: "a CSV with a header row"
        }
    );
}

#[test]
fn a_repeated_column_is_refused_rather_than_silently_resolved() {
    assert_eq!(
        refusal("name,host,Host\na,b,c\n"),
        ImportError::DuplicateColumn {
            column: "host".to_owned()
        }
    );
}

#[test]
fn an_unknown_column_is_preserved_under_its_own_namespace_and_named() {
    let preview = preview_of("name,host,Asset Tag,rack\na,a.example.com,AC-1042,R12\n");
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::UnknownColumn {
                column: "rack".to_owned()
            })
    );
    let node = find(&preview, "a");
    assert_eq!(
        node.custom_fields.get("csv.rack").map(String::as_str),
        Some("R12")
    );
    // A header that cannot be a key is reported but has nowhere to go.
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::UnknownColumn {
                column: "Asset Tag".to_owned()
            })
    );
    assert!(!node.custom_fields.keys().any(|key| key.contains(' ')));
}

#[test]
fn quoting_follows_rfc_4180() {
    let preview = preview_of(
        "name,host,description\n\
         \"a, the first\",a.example.com,\"He said \"\"hello\"\"\"\n\
         b,b.example.com,\"line one\nline two\"\n",
    );
    assert_eq!(
        find(&preview, "a, the first").description,
        "He said \"hello\""
    );
    assert_eq!(find(&preview, "b").description, "line one\nline two");
}

#[test]
fn a_semicolon_delimited_export_is_read_the_same_way() {
    let preview = preview_of("name;host;port\nweb-01;web-01.example.com;2222\n");
    assert_eq!(
        connection(&preview, "web-01").port,
        Inherited::Explicit(2222)
    );
}

#[test]
fn a_tab_delimited_export_is_read_the_same_way() {
    let preview = preview_of("name\thost\tport\nweb-01\tweb-01.example.com\t2222\n");
    assert_eq!(
        connection(&preview, "web-01").port,
        Inherited::Explicit(2222)
    );
}

#[test]
fn a_file_that_ends_inside_a_quoted_field_is_refused() {
    assert_eq!(
        refusal("name,host\n\"unterminated,a.example.com\n"),
        ImportError::Truncated {
            unit: "quoted field"
        }
    );
}

#[test]
fn a_row_with_an_unusable_host_is_skipped_and_named() {
    let preview = preview_of("name,host\nbroken,not a hostname\nfine,fine.example.com\n\nempty,\n");
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().skipped, 2);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "broken".to_owned(),
        reason: SkipReason::UnusableHost
    }));
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "empty".to_owned(),
        reason: SkipReason::Empty
    }));
}

#[test]
fn a_protocol_the_domain_model_will_not_accept_is_skipped() {
    let preview = preview_of("name,host,protocol\na,a.example.com,not a protocol\n");
    assert_eq!(preview.report().counts().connections, 0);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "a".to_owned(),
        reason: SkipReason::UnsupportedKind
    }));
}

#[test]
fn a_row_with_more_or_fewer_fields_than_the_header_is_still_read() {
    let preview = preview_of(
        "name,host,port\n\
         short,short.example.com\n\
         long,long.example.com,2222,extra,fields\n",
    );
    assert_eq!(connection(&preview, "short").port, Inherited::Inherit);
    assert_eq!(connection(&preview, "long").port, Inherited::Explicit(2222));
}

#[test]
fn a_folder_path_deeper_than_the_limit_is_refused() {
    let limits = Limits {
        max_depth: 3,
        ..Limits::new()
    };
    let deep = format!(
        "name,folder,host\na,{},a.example.com\n",
        (0..16).map(|i| format!("f{i}/")).collect::<String>()
    );
    let Err(err) = parse(deep.as_bytes(), &limits) else {
        panic!("a folder path past the depth limit must be refused");
    };
    assert_eq!(err, ImportError::TooDeep { limit: 3 });
}

#[test]
fn an_enormous_field_is_refused_rather_than_allocated() {
    let limits = Limits {
        max_value_bytes: 64,
        ..Limits::new()
    };
    let wide = format!("name,host\n{},a.example.com\n", "x".repeat(4096));
    let Err(err) = parse(wide.as_bytes(), &limits) else {
        panic!("an oversized field must be refused");
    };
    assert_eq!(
        err,
        ImportError::ValueTooLong {
            limit: 64,
            unit: "field"
        }
    );
}

#[test]
fn a_byte_order_mark_from_a_spreadsheet_does_not_break_the_header() {
    let preview = parse(
        "\u{feff}name,host\nweb-01,web-01.example.com\n".as_bytes(),
        &Limits::new(),
    )
    .unwrap();
    assert_eq!(preview.report().counts().connections, 1);
}

#[test]
fn the_preview_becomes_a_tree_the_domain_model_accepts() {
    let preview = preview_of(INVENTORY);
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| {
            let sealed = node.needs_sealing().then(|| vec![0xaa; 48]);
            node.into_node(1_700_000_000_000, sealed).unwrap()
        })
        .collect();
    let tree = Tree::from_nodes(nodes).unwrap();
    assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());

    let web01 = tree
        .nodes()
        .find(|node| node.name == "web-01")
        .map(|node| node.id)
        .unwrap();
    let effective = tree.effective_connection(web01).unwrap();
    assert_eq!(effective.port.value, Some(22));
    assert_eq!(effective.gateway.value.hops.len(), 1);
    assert!(effective.credential.value.is_some());
}

#[test]
fn no_password_from_the_file_reaches_a_summary_or_a_report() {
    let preview = preview_of(INVENTORY);
    let rendered = format!(
        "{}{}{preview:?}",
        serde_json::to_string(&preview.summaries()).unwrap(),
        serde_json::to_string(preview.report()).unwrap()
    );
    assert!(!rendered.contains("hunter2"));
    assert!(!rendered.contains("s3cret"));
}
