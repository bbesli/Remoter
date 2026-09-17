//! The JSON writer: the tree as the vault holds it, less its secrets.
//!
//! The one format that loses nothing but secrets. Inheritance stays as the
//! vault stores it — `"Inherit"`, `{"Explicit": 2222}`, `"Default"` — as do
//! protocol settings, custom fields, groups, icons and colours, so the file is
//! what a script or a diff reads to find out what a vault really says. Every
//! type inside a node serialises exactly as `remoter-core` serialises it, which
//! is the vault's own record format; the envelope around the nodes is this
//! module's.
//!
//! ```json
//! {
//!   "format": "remoter-tree",
//!   "version": 1,
//!   "generator": "Remoter 0.1.0",
//!   "exported_at": 1760000000000,
//!   "secrets": "excluded",
//!   "root": null,
//!   "nodes": [ … ],
//!   "outside": [ … ]
//! }
//! ```
//!
//! `nodes` lists parents before children and siblings in display order. A
//! credential says which kind of secret it holds — `"Password"`,
//! `{"PrivateKey": {"format": "OpenSsh", "has_passphrase": true}}` — and never
//! the secret or its ciphertext. `outside` names, by id, kind and name only, the
//! nodes that something in the export refers to but that are not in it: the
//! shared credential a folder uses from elsewhere in the vault, a jump host in
//! another folder.
//!
//! [`crate::native::parse_json`] reads it back, and a round-trip test holds the
//! two to each other: every node comes back as it was, less its secrets.

use std::collections::{BTreeMap, BTreeSet};

use remoter_core::{
    ConnectionProps, CoreError, FolderProps, GroupProps, Inherited, KeyFormat, Node, NodeId,
    NodeKind, NodeRef, ProtocolId, SecretKind, Tag, Tree,
};
use serde::Serialize;

use super::{ExportError, ExportNote, ExportReport, Scope};

/// The document's `format` value.
pub(super) const FORMAT: &str = "remoter-tree";

/// The document's `version` value. Raised when a reader of an older document
/// would misread a newer one.
pub(super) const VERSION: u32 = 1;

#[derive(Serialize)]
struct Document<'t> {
    format: &'static str,
    version: u32,
    generator: String,
    exported_at: i64,
    secrets: &'static str,
    root: Option<NodeId>,
    nodes: Vec<Entry<'t>>,
    outside: Vec<Outside>,
}

/// One node, as `remoter_core::Node` serialises it, less the fields that only
/// mean something inside one vault: `revision`, which is bound into secrets
/// this file does not carry, and `deleted_at`, because nothing deleted is
/// exported.
#[derive(Serialize)]
struct Entry<'t> {
    id: NodeId,
    parent_id: Option<NodeId>,
    sort_order: i64,
    kind: Kind<'t>,
    name: &'t str,
    description: &'t str,
    tags: &'t [Tag],
    icon: Option<&'t str>,
    colour: Option<&'t str>,
    created_at: i64,
    updated_at: i64,
    custom_fields: &'t BTreeMap<String, String>,
}

#[derive(Serialize)]
enum Kind<'t> {
    Folder(&'t FolderProps),
    Connection(&'t ConnectionProps),
    Credential(Credential<'t>),
    Group(&'t GroupProps),
    Separator,
}

/// `remoter_core::CredentialProps` with its sealed fields replaced by what
/// kind of thing they hold.
#[derive(Serialize)]
struct Credential<'t> {
    attached_to: Option<NodeId>,
    username: &'t str,
    domain: Option<&'t str>,
    secret: Secret<'t>,
    has_totp: bool,
    expires_at: Option<i64>,
    allowed_protocols: &'t [ProtocolId],
}

/// Which kind of secret a credential holds.
///
/// Built by matching on the variant and never binding a sealed field: the
/// ciphertext is not read here, let alone copied.
#[derive(Serialize)]
enum Secret<'t> {
    Password,
    PrivateKey {
        format: KeyFormat,
        has_passphrase: bool,
    },
    /// No material is stored for these at all, only which agent identity to
    /// use.
    Agent {
        comment_filter: Option<&'t str>,
    },
    /// A reference to somewhere else — a key file path, a secret manager's
    /// lookup key — and not the secret.
    External {
        provider: &'t str,
        reference: &'t str,
    },
    Certificate,
}

impl<'t> Secret<'t> {
    fn of(kind: &'t SecretKind) -> Self {
        match kind {
            SecretKind::Password { .. } => Self::Password,
            SecretKind::PrivateKey {
                sealed_passphrase,
                format,
                ..
            } => Self::PrivateKey {
                format: *format,
                has_passphrase: sealed_passphrase.is_some(),
            },
            SecretKind::Agent { comment_filter } => Self::Agent {
                comment_filter: comment_filter.as_deref(),
            },
            SecretKind::External {
                provider,
                reference,
            } => Self::External {
                provider: provider.as_str(),
                reference: reference.as_str(),
            },
            SecretKind::Certificate { .. } => Self::Certificate,
        }
    }
}

/// A node referred to from inside the export and not in it.
#[derive(Serialize, PartialEq, Eq, PartialOrd, Ord)]
struct Outside {
    id: NodeId,
    kind: &'static str,
    name: String,
    deleted: bool,
}

pub(super) fn write(
    tree: &Tree,
    scope: &Scope<'_>,
    report: &mut ExportReport,
    now: i64,
) -> Result<Vec<u8>, ExportError> {
    let mut nodes = Vec::with_capacity(scope.nodes.len());
    let mut outside: BTreeSet<Outside> = BTreeSet::new();

    for node in &scope.nodes {
        for reference in references(node) {
            if scope.contains(reference.id()) {
                continue;
            }
            let target = match reference {
                NodeRef::Deleted { id, name } => Outside {
                    id: *id,
                    kind: "deleted",
                    name: name.clone(),
                    deleted: true,
                },
                NodeRef::Live(id) => match tree.get(*id) {
                    Some(target) => Outside {
                        id: *id,
                        kind: target.kind.label(),
                        name: target.name.clone(),
                        deleted: target.deleted_at.is_some(),
                    },
                    None => return Err(CoreError::NodeNotFound(*id).into()),
                },
            };
            report.note(ExportNote::OutsideReference {
                item: node.name.clone(),
                target: target.name.clone(),
            });
            outside.insert(target);
        }

        let kind = match &node.kind {
            NodeKind::Folder(props) => Kind::Folder(props),
            NodeKind::Connection(props) => Kind::Connection(props),
            NodeKind::Credential(props) => Kind::Credential(Credential {
                attached_to: props.attached_to,
                username: &props.username,
                domain: props.domain.as_deref(),
                secret: Secret::of(&props.secret),
                has_totp: props.totp.is_some(),
                expires_at: props.expires_at,
                allowed_protocols: &props.allowed_protocols,
            }),
            NodeKind::Group(props) => Kind::Group(props),
            NodeKind::Separator => Kind::Separator,
        };
        nodes.push(Entry {
            id: node.id,
            // The export's own root has no parent in the file.
            parent_id: node.parent_id.filter(|parent| scope.contains(*parent)),
            sort_order: node.sort_order,
            kind,
            name: &node.name,
            description: &node.description,
            tags: &node.tags,
            icon: node.icon.as_deref(),
            colour: node.colour.as_deref(),
            created_at: node.created_at,
            updated_at: node.updated_at,
            custom_fields: &node.custom_fields,
        });
        report.written += 1;
    }

    let document = Document {
        format: FORMAT,
        version: VERSION,
        generator: format!("Remoter {}", env!("CARGO_PKG_VERSION")),
        exported_at: now,
        secrets: "excluded",
        root: scope.root,
        nodes,
        outside: outside.into_iter().collect(),
    };
    let mut bytes =
        serde_json::to_vec_pretty(&document).map_err(|err| ExportError::Encode(err.to_string()))?;
    bytes.push(b'\n');
    Ok(bytes)
}

/// Every node another one refers to: a credential, the hops of a route and
/// their credentials, a group's members.
fn references(node: &Node) -> Vec<&NodeRef> {
    let mut out = Vec::new();
    let (credential, gateway) = match &node.kind {
        NodeKind::Folder(props) => (&props.credential, &props.gateway),
        NodeKind::Connection(props) => (&props.credential, &props.gateway),
        NodeKind::Group(props) => {
            out.extend(props.members.iter());
            return out;
        }
        _ => return out,
    };
    if let Inherited::Explicit(credential) = credential {
        out.push(credential.as_node_ref());
    }
    if let Inherited::Explicit(chain) = gateway {
        for hop in &chain.hops {
            out.push(&hop.node);
            if let Some(credential) = &hop.credential {
                out.push(credential.as_node_ref());
            }
        }
    }
    out
}
