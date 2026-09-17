//! Importing Remoter's own exports.
//!
//! The other importers map another tool's idea of a connection onto this one.
//! Remoter's own exports need no mapping: they carry `remoter_core::Node`s. What
//! they need instead is to be *put down* in a vault that already has nodes of
//! its own — possibly the very vault they came from, whose ids they still
//! carry. [`graft`] does that: new identities for everything, every reference
//! among the nodes following its node, the export's top level placed under the
//! folder the user chose, and whatever the nodes point at that did not come
//! with them turned into a tombstone that says what is missing rather than a
//! dangling id that says nothing.
//!
//! This module reads no file and opens no archive. The `.rmtr` envelope is
//! `remoter_vault::archive`'s; what reaches here is the nodes it held.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use remoter_core::{
    ConnectionProps, CredentialProps, FolderProps, GroupProps, KeyFormat, Node, NodeId, NodeKind,
    ProtocolId, SecretKind, Tag, Tree, rekey, validate_node,
};
use serde::Deserialize;

use crate::error::ImportError;
use crate::limits::Limits;
use crate::preview::NodeSummary;
use crate::report::{Finding, ImportReport, SourceFormat};
use crate::xml::as_text;

/// The `format` a Remoter JSON export declares.
const JSON_FORMAT: &str = "remoter-tree";

/// The newest JSON export version this build reads.
const JSON_VERSION: u32 = 1;

#[derive(Deserialize)]
struct JsonDocument {
    format: String,
    version: u32,
    #[serde(default)]
    nodes: Vec<JsonEntry>,
}

#[derive(Deserialize)]
struct JsonEntry {
    id: NodeId,
    #[serde(default)]
    parent_id: Option<NodeId>,
    #[serde(default)]
    sort_order: i64,
    kind: JsonKind,
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    tags: Vec<Tag>,
    #[serde(default)]
    icon: Option<String>,
    #[serde(default)]
    colour: Option<String>,
    #[serde(default)]
    custom_fields: BTreeMap<String, String>,
}

#[derive(Deserialize)]
enum JsonKind {
    Folder(FolderProps),
    Connection(ConnectionProps),
    Credential(JsonCredential),
    Group(GroupProps),
    Separator,
}

#[derive(Deserialize)]
struct JsonCredential {
    #[serde(default)]
    attached_to: Option<NodeId>,
    username: String,
    #[serde(default)]
    domain: Option<String>,
    secret: JsonSecret,
    #[serde(default)]
    expires_at: Option<i64>,
    #[serde(default)]
    allowed_protocols: Vec<ProtocolId>,
}

#[derive(Deserialize)]
enum JsonSecret {
    Password,
    PrivateKey {
        format: KeyFormat,
        #[serde(default)]
        has_passphrase: bool,
    },
    Agent {
        #[serde(default)]
        comment_filter: Option<String>,
    },
    External {
        provider: String,
        reference: String,
    },
    Certificate,
}

/// Reads the JSON document Remoter's export writes back into nodes.
///
/// The document says which kind of secret each credential holds and never the
/// secret, so a credential that held one comes back holding `placeholder` —
/// the vault's own marker for material not yet sealed — and no material. It
/// keeps its kind, its account and its restrictions, and asks for its password
/// or key the first time it is used; the report counts how many will. A TOTP
/// configuration is sealed material too and does not come back at all.
///
/// Bounded like every importer: the input size, the node count, and
/// `serde_json`'s own nesting limit. Nothing here is validated against the
/// domain model — [`graft`] does that for every node on its way in.
///
/// # Errors
///
/// [`ImportError::TooLarge`], [`ImportError::NotUtf8`],
/// [`ImportError::MalformedJson`], [`ImportError::WrongFormat`] for JSON that
/// is not a Remoter export, [`ImportError::UnsupportedExport`] for a newer
/// one, and [`ImportError::TooManyNodes`].
pub fn parse_json(
    bytes: &[u8],
    limits: &Limits,
    placeholder: &[u8],
) -> Result<(Vec<Node>, ImportReport), ImportError> {
    let text = as_text(bytes, limits)?;
    let document: JsonDocument = serde_json::from_str(&text).map_err(|err| {
        if err.is_data() {
            ImportError::WrongFormat {
                expected: "a Remoter JSON export",
            }
        } else {
            ImportError::MalformedJson {
                line: err.line(),
                column: err.column(),
            }
        }
    })?;
    if document.format != JSON_FORMAT {
        return Err(ImportError::WrongFormat {
            expected: "a Remoter JSON export",
        });
    }
    if document.version > JSON_VERSION {
        return Err(ImportError::UnsupportedExport {
            version: document.version,
        });
    }
    if document.nodes.len() > limits.max_nodes {
        return Err(ImportError::TooManyNodes {
            limit: limits.max_nodes,
        });
    }

    let mut without_secret = 0usize;
    let nodes: Vec<Node> = document
        .nodes
        .into_iter()
        .map(|entry| {
            let kind = match entry.kind {
                JsonKind::Folder(props) => NodeKind::Folder(props),
                JsonKind::Connection(props) => NodeKind::Connection(props),
                JsonKind::Group(props) => NodeKind::Group(props),
                JsonKind::Separator => NodeKind::Separator,
                JsonKind::Credential(credential) => {
                    let sealed = || placeholder.to_vec();
                    let secret = match credential.secret {
                        JsonSecret::Password => {
                            without_secret += 1;
                            SecretKind::Password { sealed: sealed() }
                        }
                        JsonSecret::PrivateKey {
                            format,
                            has_passphrase,
                        } => {
                            without_secret += 1;
                            SecretKind::PrivateKey {
                                sealed_key: sealed(),
                                sealed_passphrase: has_passphrase.then(sealed),
                                format,
                            }
                        }
                        JsonSecret::Certificate => {
                            without_secret += 1;
                            SecretKind::Certificate {
                                sealed_cert: sealed(),
                                sealed_key: sealed(),
                            }
                        }
                        JsonSecret::Agent { comment_filter } => {
                            SecretKind::Agent { comment_filter }
                        }
                        JsonSecret::External {
                            provider,
                            reference,
                        } => SecretKind::External {
                            provider,
                            reference,
                        },
                    };
                    NodeKind::Credential(CredentialProps {
                        attached_to: credential.attached_to,
                        username: credential.username,
                        domain: credential.domain,
                        secret,
                        totp: None,
                        expires_at: credential.expires_at,
                        allowed_protocols: credential.allowed_protocols,
                    })
                }
            };
            Node {
                id: entry.id,
                parent_id: entry.parent_id,
                sort_order: entry.sort_order,
                kind,
                name: entry.name,
                description: entry.description,
                tags: entry.tags,
                icon: entry.icon,
                colour: entry.colour,
                created_at: 0,
                updated_at: 0,
                revision: 1,
                custom_fields: entry.custom_fields,
                deleted_at: None,
            }
        })
        .collect();

    let mut report = report(SourceFormat::RemoterJson, &nodes, 0);
    if without_secret > 0 {
        report.push(
            limits,
            Finding::SecretsNotCarried {
                count: without_secret,
            },
        );
    }
    Ok((nodes, report))
}

/// Nodes ready to be inserted into a tree, parents before children.
#[derive(Debug)]
pub struct Grafted {
    /// The nodes, with their new ids.
    pub nodes: Vec<Node>,
    /// Each imported node's id in the export, mapped to its new one. Secrets
    /// are carried by the export's ids and follow their node through this.
    pub ids: HashMap<NodeId, NodeId>,
    /// Nodes left out: the ones the user excluded, everything under them, and
    /// the credentials that belonged to them.
    pub excluded: usize,
    /// References to nodes that are neither in the import nor in the vault,
    /// now tombstones.
    pub tombstoned: usize,
}

/// Prepares exported nodes for insertion into `destination`.
///
/// `excluded` are ids *in the export* the user unticked; a folder excluded
/// takes everything under it, and a connection excluded takes the credential
/// attached to it. `parent` is where the export's top level goes, `base_sort`
/// where among that folder's children it starts, and `now` stamps every node
/// as created by this import.
///
/// # Errors
///
/// [`ImportError::Validation`] for a node the domain model refuses, and
/// [`ImportError::Graft`] for nodes whose parent links do not form a tree —
/// a parent that is neither in the export nor its top level, or a cycle.
pub fn graft(
    nodes: Vec<Node>,
    excluded: &BTreeSet<NodeId>,
    destination: &Tree,
    parent: Option<NodeId>,
    base_sort: i64,
    now: i64,
) -> Result<Grafted, ImportError> {
    let total = nodes.len();
    let present: HashSet<NodeId> = nodes.iter().map(|node| node.id).collect();

    // Close the exclusion over descendants and owned credentials. Iterated to
    // a fixed point rather than walked, so the order the nodes arrive in does
    // not matter; each pass adds at least one id or stops.
    let mut dropped: HashSet<NodeId> = excluded.iter().copied().collect();
    loop {
        let before = dropped.len();
        for node in &nodes {
            let under_dropped = node.parent_id.is_some_and(|p| dropped.contains(&p));
            let owner_dropped = node
                .kind
                .as_credential()
                .and_then(|credential| credential.attached_to)
                .is_some_and(|owner| dropped.contains(&owner));
            if under_dropped || owner_dropped {
                dropped.insert(node.id);
            }
        }
        if dropped.len() == before {
            break;
        }
    }

    let names: HashMap<NodeId, String> = nodes
        .iter()
        .map(|node| (node.id, node.name.clone()))
        .collect();
    let mut kept: Vec<Node> = nodes
        .into_iter()
        .filter(|node| !dropped.contains(&node.id))
        .collect();
    let excluded_count = total - kept.len();

    // A top-level node is one whose parent did not come with it. Remembered
    // before the ids change, because afterwards "not in the export" and "not
    // yet rekeyed" look the same.
    let top_level: HashSet<NodeId> = kept
        .iter()
        .filter(|node| {
            node.parent_id
                .is_none_or(|p| !present.contains(&p) || dropped.contains(&p))
        })
        .map(|node| node.id)
        .collect();

    let old_ids: Vec<NodeId> = kept.iter().map(|node| node.id).collect();
    let ids = rekey(&mut kept);
    let new_ids: HashSet<NodeId> = ids.values().copied().collect();

    let mut tombstoned = 0usize;
    let mut sort = base_sort;
    for (node, old) in kept.iter_mut().zip(old_ids) {
        if top_level.contains(&old) {
            node.parent_id = parent;
            node.sort_order = sort;
            sort = sort.saturating_add(1);
        }
        node.created_at = now;
        node.updated_at = now;
        node.revision = 1;
        node.deleted_at = None;
        tombstoned += node.tombstone_references(
            |target| {
                new_ids.contains(&target)
                    || destination
                        .get(target)
                        .is_some_and(|found| found.deleted_at.is_none())
            },
            |target| names.get(&target).cloned().unwrap_or_default(),
        );
        if let NodeKind::Credential(credential) = &mut node.kind {
            if credential
                .attached_to
                .is_some_and(|owner| !new_ids.contains(&owner))
            {
                credential.attached_to = None;
            }
        }
        validate_node(node)?;
    }

    let nodes = parents_first(kept, parent)?;
    Ok(Grafted {
        nodes,
        ids,
        excluded: excluded_count,
        tombstoned,
    })
}

/// Orders nodes so every parent comes before its children.
fn parents_first(mut nodes: Vec<Node>, root: Option<NodeId>) -> Result<Vec<Node>, ImportError> {
    let mut placed: HashSet<NodeId> = HashSet::new();
    let mut out = Vec::with_capacity(nodes.len());
    while !nodes.is_empty() {
        let before = nodes.len();
        let (ready, waiting): (Vec<Node>, Vec<Node>) = nodes.into_iter().partition(|node| {
            node.parent_id.is_none()
                || node.parent_id == root
                || node.parent_id.is_some_and(|p| placed.contains(&p))
        });
        for node in ready {
            placed.insert(node.id);
            out.push(node);
        }
        nodes = waiting;
        if nodes.len() == before {
            return Err(ImportError::Graft);
        }
    }
    Ok(out)
}

/// The secret-free description of exported nodes, for the preview.
///
/// `with_secrets` names the nodes, by their ids in the export, that carry a
/// secret.
#[must_use]
pub fn summaries(nodes: &[Node], with_secrets: &HashSet<NodeId>) -> Vec<NodeSummary> {
    nodes
        .iter()
        .map(|node| NodeSummary::of_node(node, with_secrets.contains(&node.id)))
        .collect()
}

/// The report for exported nodes: counts, and how many secrets came with them.
#[must_use]
pub fn report(source: SourceFormat, nodes: &[Node], secrets: usize) -> ImportReport {
    let mut report = ImportReport::new(source);
    let counts = report.counts_mut();
    for node in nodes {
        match node.kind {
            NodeKind::Folder(_) => counts.folders += 1,
            NodeKind::Connection(_) => counts.connections += 1,
            NodeKind::Credential(_) => counts.credentials += 1,
            _ => {}
        }
    }
    counts.secrets = secrets;
    report
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use remoter_core::{
        ConnectionProps, CredentialProps, CredentialRef, GatewayHop, Inherited, NodeRef, SecretKind,
    };

    use super::*;

    const NOW: i64 = 1_770_000_000_000;

    fn folder(name: &str, parent: Option<NodeId>) -> Node {
        let mut node = Node::new(NodeKind::folder(), name, 1);
        node.parent_id = parent;
        node
    }

    fn connection(name: &str, parent: Option<NodeId>) -> Node {
        let mut node = Node::new(
            NodeKind::Connection(ConnectionProps::new("ssh", format!("{name}.example")).unwrap()),
            name,
            1,
        );
        node.parent_id = parent;
        node
    }

    fn credential(name: &str, parent: Option<NodeId>, owner: Option<NodeId>) -> Node {
        let mut props = CredentialProps::new(name, SecretKind::Password { sealed: vec![0] });
        props.attached_to = owner;
        let mut node = Node::new(NodeKind::Credential(props), name, 1);
        node.parent_id = parent;
        node
    }

    fn uses(node: &mut Node, credential: NodeId) {
        if let NodeKind::Connection(props) = &mut node.kind {
            props.credential = Inherited::Explicit(CredentialRef::live(credential));
        }
    }

    /// A folder with a connection, its own credential, and a jump host whose
    /// shared credential lives outside the folder.
    fn export() -> (Vec<Node>, [NodeId; 5]) {
        let estate = folder("Estate", None);
        let mut web = connection("web", Some(estate.id));
        let own = credential("web", Some(estate.id), Some(web.id));
        uses(&mut web, own.id);
        let mut bastion = connection("bastion", None);
        let shared = credential("svc", None, None);
        uses(&mut bastion, shared.id);
        if let NodeKind::Connection(props) = &mut web.kind {
            props.gateway =
                Inherited::Explicit([GatewayHop::new(bastion.id)].into_iter().collect());
        }
        let ids = [estate.id, web.id, own.id, bastion.id, shared.id];
        (vec![estate, web, own, bastion, shared], ids)
    }

    #[test]
    fn an_export_goes_back_into_the_vault_it_came_from_as_new_nodes() {
        let (nodes, [estate, web, own, bastion, shared]) = export();
        // The destination already holds the originals: every id is taken.
        let mut target = Tree::from_nodes(nodes.iter().cloned()).unwrap();
        let into = folder("Imported", None);
        let into_id = into.id;
        target.insert(into).unwrap();

        let grafted = graft(nodes, &BTreeSet::new(), &target, Some(into_id), 10, NOW).unwrap();
        assert_eq!(grafted.nodes.len(), 5);
        assert_eq!(grafted.excluded, 0);
        assert_eq!(grafted.tombstoned, 0);
        for old in [estate, web, own, bastion, shared] {
            let new = grafted.ids[&old];
            assert_ne!(new, old);
        }

        let find = |old: NodeId| {
            grafted
                .nodes
                .iter()
                .find(|n| n.id == grafted.ids[&old])
                .unwrap()
        };
        // The export's top level lands under the chosen folder, in order.
        assert_eq!(find(estate).parent_id, Some(into_id));
        assert_eq!(find(estate).sort_order, 10);
        assert_eq!(find(bastion).parent_id, Some(into_id));
        assert_eq!(find(bastion).sort_order, 11);
        assert_eq!(find(shared).sort_order, 12);
        // Everything below keeps its place, under its parent's new id.
        assert_eq!(find(web).parent_id, Some(grafted.ids[&estate]));
        // References follow.
        assert_eq!(
            find(web).kind.as_connection().unwrap().credential,
            Inherited::Explicit(CredentialRef::live(grafted.ids[&own]))
        );
        assert_eq!(
            find(own).kind.as_credential().unwrap().attached_to,
            Some(grafted.ids[&web])
        );
        let Inherited::Explicit(chain) = &find(web).kind.as_connection().unwrap().gateway else {
            panic!("no chain");
        };
        assert_eq!(chain.hops[0].node, NodeRef::live(grafted.ids[&bastion]));
        assert!(
            grafted
                .nodes
                .iter()
                .all(|n| n.created_at == NOW && n.revision == 1)
        );

        // And the result is a tree the vault accepts, parents first.
        for node in grafted.nodes {
            target.insert(node).unwrap();
        }
        assert!(
            target.validate_all().is_empty(),
            "{:?}",
            target.validate_all()
        );
    }

    #[test]
    fn what_the_user_unticks_takes_what_depends_on_it_and_leaves_a_named_gap() {
        let (nodes, [estate, web, own, bastion, shared]) = export();
        let excluded: BTreeSet<NodeId> = [web, shared].into_iter().collect();
        let grafted = graft(nodes, &excluded, &Tree::new(), None, 0, NOW).unwrap();

        // web, the credential it owns, and svc.
        assert_eq!(grafted.excluded, 3);
        assert!(!grafted.ids.contains_key(&own));
        assert!(grafted.ids.contains_key(&estate));
        let bastion = grafted
            .nodes
            .iter()
            .find(|n| n.id == grafted.ids[&bastion])
            .unwrap();
        // The bastion's credential did not come: a tombstone that says which.
        assert_eq!(
            bastion.kind.as_connection().unwrap().credential,
            Inherited::Explicit(CredentialRef::deleted(shared, "svc"))
        );
        assert_eq!(grafted.tombstoned, 1);
    }

    #[test]
    fn a_reference_to_something_the_vault_already_has_stays_live() {
        let svc = credential("svc", None, None);
        let mut target = Tree::new();
        let svc_id = svc.id;
        target.insert(svc).unwrap();

        let mut web = connection("web", None);
        uses(&mut web, svc_id);
        let grafted = graft(vec![web], &BTreeSet::new(), &target, None, 0, NOW).unwrap();
        assert_eq!(
            grafted.nodes[0].kind.as_connection().unwrap().credential,
            Inherited::Explicit(CredentialRef::live(svc_id))
        );
        assert_eq!(grafted.tombstoned, 0);
    }

    #[test]
    fn children_before_parents_are_put_in_order_and_a_cycle_is_refused() {
        let parent = folder("Estate", None);
        let child = folder("Team", Some(parent.id));
        let leaf = connection("web", Some(child.id));
        let grafted = graft(
            vec![leaf, child, parent],
            &BTreeSet::new(),
            &Tree::new(),
            None,
            0,
            NOW,
        )
        .unwrap();
        let names: Vec<&str> = grafted.nodes.iter().map(|n| n.name.as_str()).collect();
        assert_eq!(names, ["Estate", "Team", "web"]);

        let mut a = folder("a", None);
        let mut b = folder("b", Some(a.id));
        a.parent_id = Some(b.id);
        b.parent_id = Some(a.id);
        assert!(matches!(
            graft(vec![a, b], &BTreeSet::new(), &Tree::new(), None, 0, NOW),
            Err(ImportError::Graft)
        ));
    }

    #[test]
    fn the_preview_of_an_export_says_what_carries_a_secret_and_never_what_it_is() {
        let (nodes, [_, web, own, _, _]) = export();
        let with: HashSet<NodeId> = [own].into_iter().collect();
        let summaries = summaries(&nodes, &with);
        let own_summary = summaries.iter().find(|s| s.id == own).unwrap();
        assert!(own_summary.has_secret);
        assert_eq!(own_summary.username.as_deref(), Some("web"));
        let web_summary = summaries.iter().find(|s| s.id == web).unwrap();
        assert_eq!(web_summary.gateway_hops, 1);
        assert_eq!(web_summary.host.as_deref(), Some("web.example"));

        let report = report(SourceFormat::RemoterArchive, &nodes, 1);
        assert_eq!(report.counts().connections, 2);
        assert_eq!(report.counts().credentials, 2);
        assert_eq!(report.counts().folders, 1);
        assert_eq!(report.counts().secrets, 1);
    }
}
