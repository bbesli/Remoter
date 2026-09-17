//! The tree an import would create, before anything is written.
//!
//! `docs/features/import-export.md` is explicit that nothing touches the vault
//! until the user confirms the preview, so this crate produces one and stops.
//! The preview is not a `Vec<Node>` because a [`Node`] cannot be built without
//! sealed secret material, and sealing needs a vault this crate deliberately
//! knows nothing about. A [`PreviewNode`] is therefore everything a node will
//! be *except* the sealing, plus the plaintext the vault is about to seal.
//!
//! Neither [`PreviewNode`] nor [`PreviewCredential`] implements `Serialize`, and
//! that is not an omission. They carry recovered passwords, and the interface
//! never holds one: it requests an action and the core performs it.
//! [`PreviewNode::summary`] is the shape that crosses the IPC boundary — same
//! tree, same counts, no secrets.

use std::collections::BTreeMap;

use remoter_core::{
    ConnectionProps, CredentialProps, FolderProps, Inherited, Node, NodeId, NodeKind, ProtocolId,
    SecretKind, Tag, validate_node,
};
use serde::{Deserialize, Serialize};

use crate::error::ImportError;
use crate::limits::Limits;
use crate::report::{ImportReport, SourceFormat};
use crate::secret::ImportedSecret;

/// A credential as the source described it, with its secret still in plaintext.
#[derive(Debug)]
pub struct PreviewCredential {
    /// The account name.
    pub username: String,
    /// The Windows or Kerberos domain, where the source had one.
    pub domain: Option<String>,
    /// The secret, sealed or not depending on where it came from.
    pub secret: PreviewSecret,
    /// Protocols this credential may be used with.
    ///
    /// `docs/features/import-export.md`: "Imported credentials carry a
    /// `Purpose` restriction matching their source protocol." An RDP password
    /// that arrives from mRemoteNG cannot then be picked up by an SSH
    /// connection that inherited it from a shared parent.
    pub allowed_protocols: Vec<ProtocolId>,
}

/// Where a previewed credential's secret stands.
///
/// `PartialEq` compares content, which is what deduplication needs. It is not
/// constant time and is not used to gate anything.
#[derive(Debug, PartialEq, Eq)]
pub enum PreviewSecret {
    /// A password recovered from the file. The vault seals it at commit time;
    /// until then it is a [`ImportedSecret`] and nothing else.
    Password(ImportedSecret),
    /// A secret that needs no sealing because no material came across: an
    /// agent delegation, or a reference to a key file left on disk.
    Unsealed(SecretKind),
}

impl PreviewSecret {
    /// Whether the vault has to seal something before this becomes a node.
    #[must_use]
    pub const fn needs_sealing(&self) -> bool {
        matches!(self, Self::Password(_))
    }
}

/// What a previewed node is.
#[derive(Debug)]
pub enum PreviewKind {
    /// An organising node.
    Folder(FolderProps),
    /// A target to connect to.
    Connection(ConnectionProps),
    /// A username and a not-yet-sealed secret.
    Credential(PreviewCredential),
}

impl PreviewKind {
    /// A short, stable name for the kind.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Folder(_) => "folder",
            Self::Connection(_) => "connection",
            Self::Credential(_) => "credential",
        }
    }
}

/// One node the import would create.
#[derive(Debug)]
pub struct PreviewNode {
    /// The identity the node will be created with. Already allocated, so that
    /// gateway chains and credential references inside the preview resolve
    /// without a second pass at commit time.
    pub id: NodeId,
    /// The parent, or `None` for a node the import puts at its destination's
    /// top level.
    pub parent_id: Option<NodeId>,
    /// Position among siblings, in source order.
    pub sort_order: i64,
    /// Display name.
    pub name: String,
    /// Free-form notes carried over from the source.
    pub description: String,
    /// Tags carried over from the source.
    pub tags: Vec<Tag>,
    /// Icon reference, where the source had one this build understands.
    pub icon: Option<String>,
    /// Accent colour.
    pub colour: Option<String>,
    /// Everything the source held that has no home in the domain model,
    /// preserved verbatim under a source-namespaced key.
    pub custom_fields: BTreeMap<String, String>,
    /// What the node is.
    pub kind: PreviewKind,
}

impl PreviewNode {
    pub(crate) fn new(id: NodeId, name: String, kind: PreviewKind) -> Self {
        Self {
            id,
            parent_id: None,
            sort_order: 0,
            name,
            description: String::new(),
            tags: Vec::new(),
            icon: None,
            colour: None,
            custom_fields: BTreeMap::new(),
            kind,
        }
    }

    pub(crate) fn under(mut self, parent: Option<NodeId>, sort_order: i64) -> Self {
        self.parent_id = parent;
        self.sort_order = sort_order;
        self
    }

    /// The plaintext secret this node carries, if it carries one.
    #[must_use]
    pub fn secret(&self) -> Option<&ImportedSecret> {
        match &self.kind {
            PreviewKind::Credential(PreviewCredential {
                secret: PreviewSecret::Password(secret),
                ..
            }) => Some(secret),
            _ => None,
        }
    }

    /// Whether the vault has to seal something before this becomes a node.
    #[must_use]
    pub fn needs_sealing(&self) -> bool {
        self.secret().is_some()
    }

    /// The node this preview becomes.
    ///
    /// `sealed` is the ciphertext the vault produced from [`Self::secret`], and
    /// must be present exactly when [`Self::needs_sealing`] is true. The
    /// plaintext is dropped — and therefore zeroed — as this function returns,
    /// so a caller that seals and commits never holds two copies.
    ///
    /// `now` is a parameter for the same reason it is one on [`Node::new`]:
    /// this crate owns no clock, and a test that fixes the timestamp can
    /// compare whole trees.
    ///
    /// # Errors
    ///
    /// [`ImportError::Validation`] if the node the mapping built is not one
    /// `remoter-core` accepts, or if `sealed` does not match what the node
    /// needs. Both mean a bug in this crate rather than a problem with the
    /// file: per-item problems are reported, not raised.
    pub fn into_node(self, now: i64, sealed: Option<Vec<u8>>) -> Result<Node, ImportError> {
        let kind = match self.kind {
            PreviewKind::Folder(props) => NodeKind::Folder(props),
            PreviewKind::Connection(props) => NodeKind::Connection(props),
            PreviewKind::Credential(credential) => {
                let secret = match credential.secret {
                    PreviewSecret::Password(_) => {
                        let sealed = sealed.filter(|bytes| !bytes.is_empty()).ok_or(
                            ImportError::Validation(
                                remoter_core::ValidationError::SealedMaterialEmpty,
                            ),
                        )?;
                        SecretKind::Password { sealed }
                    }
                    PreviewSecret::Unsealed(kind) => kind,
                };
                NodeKind::Credential(CredentialProps {
                    // An imported credential is a shared one: the documents
                    // these importers read model credentials as their own
                    // entries, and inventing an owner for one would attach it
                    // to a connection the file never said it belonged to.
                    attached_to: None,
                    username: credential.username,
                    domain: credential.domain,
                    secret,
                    totp: None,
                    expires_at: None,
                    allowed_protocols: credential.allowed_protocols,
                })
            }
        };

        let node = Node {
            id: self.id,
            parent_id: self.parent_id,
            sort_order: self.sort_order,
            kind,
            name: self.name,
            description: self.description,
            tags: self.tags,
            icon: self.icon,
            colour: self.colour,
            created_at: now,
            updated_at: now,
            revision: 1,
            custom_fields: self.custom_fields,
            deleted_at: None,
        };
        validate_node(&node)?;
        Ok(node)
    }

    /// The secret-free description of this node, for the interface.
    #[must_use]
    pub fn summary(&self) -> NodeSummary {
        let mut summary = NodeSummary {
            id: self.id,
            parent_id: self.parent_id,
            sort_order: self.sort_order,
            name: self.name.clone(),
            kind: self.kind.label().to_owned(),
            protocol: None,
            host: None,
            port: None,
            port_inherited: false,
            username: None,
            domain: None,
            has_secret: false,
            credential_inherited: false,
            gateway_hops: 0,
            custom_fields: self.custom_fields.len(),
        };
        match &self.kind {
            PreviewKind::Folder(props) => {
                summary.port = props.port.explicit().copied();
                summary.port_inherited = props.port.is_inherit();
                summary.credential_inherited = props.credential.is_inherit();
                summary.gateway_hops = props.gateway.explicit().map_or(0, |g| g.hops.len());
            }
            PreviewKind::Connection(props) => {
                summary.protocol = Some(props.protocol.to_string());
                summary.host = Some(props.host.clone());
                summary.port = props.port.explicit().copied();
                summary.port_inherited = props.port.is_inherit();
                summary.credential_inherited = props.credential.is_inherit();
                summary.gateway_hops = props.gateway.explicit().map_or(0, |g| g.hops.len());
            }
            PreviewKind::Credential(credential) => {
                summary.username = Some(credential.username.clone());
                summary.domain.clone_from(&credential.domain);
                summary.has_secret = credential.secret.needs_sealing();
            }
        }
        summary
    }
}

impl NodeSummary {
    /// The summary of a node that is already in the domain model's shape — one
    /// from Remoter's own export — with whether a secret came with it.
    #[must_use]
    pub fn of_node(node: &Node, has_secret: bool) -> Self {
        let mut summary = Self {
            id: node.id,
            parent_id: node.parent_id,
            sort_order: node.sort_order,
            name: node.name.clone(),
            kind: node.kind.label().to_owned(),
            protocol: None,
            host: None,
            port: None,
            port_inherited: false,
            username: None,
            domain: None,
            has_secret,
            credential_inherited: false,
            gateway_hops: 0,
            custom_fields: node.custom_fields.len(),
        };
        if let Some(port) = node.port_field() {
            summary.port = port.explicit().copied();
            summary.port_inherited = port.is_inherit();
        }
        if let Some(credential) = node.credential_field() {
            summary.credential_inherited = credential.is_inherit();
        }
        if let Some(gateway) = node.gateway_field() {
            summary.gateway_hops = gateway.explicit().map_or(0, |g| g.hops.len());
        }
        match &node.kind {
            NodeKind::Connection(props) => {
                summary.protocol = Some(props.protocol.to_string());
                summary.host = Some(props.host.clone());
            }
            NodeKind::Credential(props) => {
                summary.username = Some(props.username.clone());
                summary.domain.clone_from(&props.domain);
            }
            _ => {}
        }
        summary
    }
}

/// A previewed node with everything secret removed.
///
/// This is what crosses the IPC boundary and what the preview screen renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSummary {
    /// The identity the node will be created with.
    pub id: NodeId,
    /// The parent.
    pub parent_id: Option<NodeId>,
    /// Position among siblings.
    pub sort_order: i64,
    /// Display name.
    pub name: String,
    /// `folder`, `connection` or `credential`.
    pub kind: String,
    /// The protocol adapter, for a connection.
    pub protocol: Option<String>,
    /// The target host, for a connection.
    pub host: Option<String>,
    /// The port, when the node sets one explicitly.
    pub port: Option<u16>,
    /// Whether the port is inherited from an ancestor.
    pub port_inherited: bool,
    /// The account name, for a credential.
    pub username: Option<String>,
    /// The domain, for a credential.
    pub domain: Option<String>,
    /// Whether a password came across with this credential. Never the password
    /// itself, and never its length.
    pub has_secret: bool,
    /// Whether the credential is inherited from an ancestor.
    pub credential_inherited: bool,
    /// How many gateway hops the node sets explicitly.
    pub gateway_hops: usize,
    /// How many custom fields were preserved.
    pub custom_fields: usize,
}

/// Everything an import would create, and the report that explains it.
#[derive(Debug)]
pub struct ImportPreview {
    nodes: Vec<PreviewNode>,
    report: ImportReport,
}

impl ImportPreview {
    /// The nodes, parents before children, siblings in source order.
    #[must_use]
    pub fn nodes(&self) -> &[PreviewNode] {
        &self.nodes
    }

    /// What came in, what could not be mapped, what needs attention.
    #[must_use]
    pub const fn report(&self) -> &ImportReport {
        &self.report
    }

    /// The secret-free view of the whole tree, for the preview screen.
    #[must_use]
    pub fn summaries(&self) -> Vec<NodeSummary> {
        self.nodes.iter().map(PreviewNode::summary).collect()
    }

    /// Takes the preview apart for the commit, which needs to own the nodes in
    /// order to seal their secrets.
    #[must_use]
    pub fn into_parts(self) -> (Vec<PreviewNode>, ImportReport) {
        (self.nodes, self.report)
    }
}

/// Accumulates a preview under a fixed set of limits.
///
/// Every node in a preview goes through here, so the node ceiling is enforced
/// in one place rather than in each of the three importers.
pub(crate) struct PreviewBuilder {
    nodes: Vec<PreviewNode>,
    report: ImportReport,
    limits: Limits,
}

impl PreviewBuilder {
    pub(crate) fn new(source: SourceFormat, limits: Limits) -> Self {
        Self {
            nodes: Vec::new(),
            report: ImportReport::new(source),
            limits,
        }
    }

    pub(crate) const fn limits(&self) -> &Limits {
        &self.limits
    }

    pub(crate) const fn report_mut(&mut self) -> &mut ImportReport {
        &mut self.report
    }

    /// Adds a node, counting it and refusing to grow past the node ceiling.
    pub(crate) fn push(&mut self, node: PreviewNode) -> Result<NodeId, ImportError> {
        if self.nodes.len() >= self.limits.max_nodes {
            return Err(ImportError::TooManyNodes {
                limit: self.limits.max_nodes,
            });
        }
        let id = node.id;
        let counts = self.report.counts_mut();
        match &node.kind {
            PreviewKind::Folder(_) => counts.folders += 1,
            PreviewKind::Connection(_) => counts.connections += 1,
            PreviewKind::Credential(credential) => {
                counts.credentials += 1;
                if credential.secret.needs_sealing() {
                    counts.secrets += 1;
                }
            }
        }
        self.nodes.push(node);
        Ok(id)
    }

    /// Borrows a node that was already pushed, so a second pass can fill in a
    /// reference that was not resolvable when the node was built.
    pub(crate) fn node_mut(&mut self, id: NodeId) -> Option<&mut PreviewNode> {
        self.nodes.iter_mut().find(|node| node.id == id)
    }

    /// Sets a connection's gateway chain, which the second pass does once every
    /// jump target has an id.
    pub(crate) fn set_gateway(
        &mut self,
        id: NodeId,
        gateway: Inherited<remoter_core::GatewayChain>,
    ) {
        if let Some(PreviewNode {
            kind: PreviewKind::Connection(props),
            ..
        }) = self.node_mut(id)
        {
            props.gateway = gateway;
        }
    }

    pub(crate) fn finish(self) -> ImportPreview {
        ImportPreview {
            nodes: self.nodes,
            report: self.report,
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use super::*;
    use crate::report::Finding;

    fn credential(secret: PreviewSecret) -> PreviewNode {
        PreviewNode::new(
            NodeId::new(),
            "svc-deploy".to_owned(),
            PreviewKind::Credential(PreviewCredential {
                username: "svc-deploy".to_owned(),
                domain: None,
                secret,
                allowed_protocols: Vec::new(),
            }),
        )
    }

    #[test]
    fn a_password_credential_needs_sealing_before_it_becomes_a_node() {
        let node = credential(PreviewSecret::Password(ImportedSecret::from("hunter2")));
        assert!(node.needs_sealing());
        assert!(node.secret().is_some());

        let Err(err) = node.into_node(0, None) else {
            panic!("a credential with an unsealed password must not become a node");
        };
        assert!(matches!(err, ImportError::Validation(_)));

        let node = credential(PreviewSecret::Password(ImportedSecret::from("hunter2")));
        let sealed = node.into_node(0, Some(vec![1, 2, 3])).unwrap();
        assert!(matches!(
            sealed.kind,
            NodeKind::Credential(CredentialProps {
                secret: SecretKind::Password { .. },
                ..
            })
        ));
    }

    #[test]
    fn an_empty_seal_is_refused_the_same_way_a_missing_one_is() {
        let node = credential(PreviewSecret::Password(ImportedSecret::from("hunter2")));
        assert!(node.into_node(0, Some(Vec::new())).is_err());
    }

    #[test]
    fn an_agent_credential_becomes_a_node_with_nothing_to_seal() {
        let node = credential(PreviewSecret::Unsealed(SecretKind::Agent {
            comment_filter: None,
        }));
        assert!(!node.needs_sealing());
        assert!(node.secret().is_none());
        assert!(node.into_node(0, None).is_ok());
    }

    #[test]
    fn a_summary_names_the_credential_but_not_the_secret() {
        let node = credential(PreviewSecret::Password(ImportedSecret::from("hunter2")));
        let summary = node.summary();
        assert!(summary.has_secret);
        assert_eq!(summary.username.as_deref(), Some("svc-deploy"));
        let json = serde_json::to_string(&summary).unwrap();
        assert!(!json.contains("hunter2"));
    }

    #[test]
    fn the_node_ceiling_is_enforced_by_the_builder() {
        let limits = Limits {
            max_nodes: 2,
            ..Limits::new()
        };
        let mut builder = PreviewBuilder::new(SourceFormat::Csv, limits);
        assert!(
            builder
                .push(credential(PreviewSecret::Unsealed(SecretKind::Agent {
                    comment_filter: None
                })))
                .is_ok()
        );
        assert!(
            builder
                .push(credential(PreviewSecret::Unsealed(SecretKind::Agent {
                    comment_filter: None
                })))
                .is_ok()
        );
        let Err(err) = builder.push(credential(PreviewSecret::Unsealed(SecretKind::Agent {
            comment_filter: None,
        }))) else {
            panic!("the third node must be refused");
        };
        assert_eq!(err, ImportError::TooManyNodes { limit: 2 });
    }

    #[test]
    fn counts_follow_what_was_pushed() {
        let mut builder = PreviewBuilder::new(SourceFormat::Csv, Limits::new());
        builder
            .push(PreviewNode::new(
                NodeId::new(),
                "f".to_owned(),
                PreviewKind::Folder(FolderProps::default()),
            ))
            .unwrap();
        builder
            .push(credential(PreviewSecret::Password(ImportedSecret::from(
                "x",
            ))))
            .unwrap();
        builder
            .report_mut()
            .push(&Limits::new(), Finding::DefaultFilePassword);
        let preview = builder.finish();
        assert_eq!(preview.report().counts().folders, 1);
        assert_eq!(preview.report().counts().credentials, 1);
        assert_eq!(preview.report().counts().secrets, 1);
        assert_eq!(preview.summaries().len(), 2);
    }
}
