//! Typed errors for the domain model.
//!
//! Two levels. [`ValidationError`] describes a value the user typed or an
//! importer produced that the model refuses to hold; it is the thing an
//! interface renders next to a form field. [`CoreError`] adds the failures that
//! only exist in the context of a whole tree — a missing parent, a cycle, a
//! depth limit — and carries a `ValidationError` when the cause was a value.
//!
//! No error variant ever carries secret material. Hostnames, node names, tags
//! and setting *keys* appear in messages because the user needs to be told
//! which one is wrong; setting *values*, credential material and TOTP
//! configuration never do.

use crate::node::NodeId;
use crate::{MAX_GATEWAY_HOPS, MAX_NAME_LEN, MAX_TREE_DEPTH};

/// A value that the domain model refuses to hold.
///
/// Enforced in `remoter-core` rather than in the interface so that the CLI and
/// the importers get the same guarantees the forms do.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ValidationError {
    /// A node name was empty.
    #[error("node name must not be empty")]
    NameEmpty,

    /// A node name exceeded [`MAX_NAME_LEN`] characters.
    #[error("node name is {len} characters; the maximum is {max}", max = MAX_NAME_LEN)]
    NameTooLong {
        /// The length that was supplied, in characters.
        len: usize,
    },

    /// A node name contained a control character.
    #[error("node name must not contain control characters")]
    NameControlChar,

    /// A description exceeded the permitted length.
    #[error("description is {len} characters; the maximum is {max}")]
    DescriptionTooLong {
        /// The length that was supplied, in characters.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },

    /// A hostname was empty.
    #[error("host must not be empty")]
    HostEmpty,

    /// A hostname was neither a DNS name, an IPv4 address nor a bracketed IPv6
    /// address.
    #[error("`{host}` is not a valid DNS name, IPv4 address or bracketed IPv6 address")]
    InvalidHost {
        /// The rejected host.
        host: String,
    },

    /// Port zero is not a connectable port.
    #[error("port must be in 1..=65535")]
    PortOutOfRange,

    /// A tag was empty, too long, or contained a disallowed character.
    #[error("`{tag}` is not a valid tag")]
    InvalidTag {
        /// The rejected tag.
        tag: String,
    },

    /// A protocol identifier was empty or contained a disallowed character.
    #[error("`{id}` is not a valid protocol identifier")]
    InvalidProtocolId {
        /// The rejected identifier.
        id: String,
    },

    /// A protocol settings key was empty or contained a disallowed character.
    ///
    /// The key is named because the specification requires rejection to say
    /// which key offended; the value is deliberately omitted.
    #[error("`{key}` is not a valid protocol settings key")]
    InvalidSettingKey {
        /// The rejected key.
        key: String,
    },

    /// A custom field key was empty or contained a disallowed character.
    #[error("`{key}` is not a valid custom field key")]
    InvalidCustomFieldKey {
        /// The rejected key.
        key: String,
    },

    /// A colour was not `#rrggbb` or `#rrggbbaa`.
    #[error("`{colour}` is not a valid colour; expected #rrggbb or #rrggbbaa")]
    InvalidColour {
        /// The rejected colour.
        colour: String,
    },

    /// An icon reference was empty or contained a control character.
    #[error("icon reference must be non-empty and free of control characters")]
    InvalidIcon,

    /// A gateway chain was longer than [`MAX_GATEWAY_HOPS`].
    #[error("gateway chain has {hops} hops; the maximum is {max}", max = MAX_GATEWAY_HOPS)]
    GatewayTooLong {
        /// The number of hops supplied.
        hops: usize,
    },

    /// The same node appeared twice in one gateway chain, or the connection
    /// appeared in its own chain.
    #[error("gateway chain visits node {hop} more than once")]
    GatewayCycle {
        /// The node that repeated.
        hop: NodeId,
    },

    /// A gateway hop referenced a node that is not in this vault.
    #[error("gateway hop references unknown node {hop}")]
    GatewayHopUnknown {
        /// The referenced node.
        hop: NodeId,
    },

    /// A gateway hop referenced a node that is not a connection.
    #[error("gateway hop {hop} is not a connection")]
    GatewayHopNotAConnection {
        /// The referenced node.
        hop: NodeId,
    },

    /// A credential reference pointed outside this vault.
    ///
    /// This is the "credential referenced from another vault" rule. In the
    /// domain model a vault *is* the tree, so a reference to an id that is
    /// neither present nor recorded as a tombstone is by definition foreign.
    #[error("credential {credential} is not in this vault")]
    CredentialUnknown {
        /// The referenced node.
        credential: NodeId,
    },

    /// A credential reference pointed at a node that is not a credential.
    #[error("node {credential} is not a credential")]
    CredentialNotACredential {
        /// The referenced node.
        credential: NodeId,
    },

    /// A node pointed at a credential that belongs to another connection.
    ///
    /// An attached credential is one connection's own. Two connections behind
    /// one attached credential would mean editing either one silently changed
    /// the other, which is what attaching exists to prevent.
    #[error("credential {credential} belongs to connection {connection}")]
    CredentialAttachedElsewhere {
        /// The referenced credential.
        credential: NodeId,
        /// The connection it belongs to.
        connection: NodeId,
    },

    /// An attached credential named a connection that is not in this vault.
    #[error("credential {credential} is attached to unknown node {connection}")]
    CredentialAttachmentUnknown {
        /// The attached credential.
        credential: NodeId,
        /// The node it claims to belong to.
        connection: NodeId,
    },

    /// An attached credential named a node that is not a connection.
    #[error("credential {credential} is attached to node {connection}, which is not a connection")]
    CredentialAttachmentNotAConnection {
        /// The attached credential.
        credential: NodeId,
        /// The node it claims to belong to.
        connection: NodeId,
    },

    /// A credential restricted to a set of protocols was used by a connection
    /// speaking a different one.
    #[error("credential {credential} may not be used for protocol `{protocol}`")]
    CredentialPurpose {
        /// The referenced credential.
        credential: NodeId,
        /// The protocol the connection speaks.
        protocol: String,
    },

    /// A username exceeded the permitted length.
    #[error("username is {len} characters; the maximum is {max}")]
    UsernameTooLong {
        /// The length that was supplied, in characters.
        len: usize,
        /// The permitted maximum.
        max: usize,
    },

    /// A username or domain contained a control character.
    #[error("username and domain must not contain control characters")]
    IdentityControlChar,

    /// An external secret provider or reference was empty.
    #[error("an external credential needs both a provider and a reference")]
    ExternalCredentialIncomplete,

    /// Sealed credential material was present but empty.
    ///
    /// The length of a ciphertext is not secret; its content is, and is never
    /// named here.
    #[error("sealed credential material must not be empty")]
    SealedMaterialEmpty,

    /// A grid layout had a zero row or column count.
    #[error("a grid layout needs at least one row and one column")]
    InvalidLayout,

    /// A group member reference pointed at a node that is not in this vault.
    #[error("group member references unknown node {member}")]
    GroupMemberUnknown {
        /// The referenced node.
        member: NodeId,
    },

    /// An on-connect or on-disconnect action was empty.
    #[error("an action must not be empty")]
    EmptyAction,

    /// A reconnect policy had contradictory parameters.
    #[error("reconnect policy needs at least one attempt and a backoff that does not shrink")]
    InvalidReconnectPolicy,

    /// A timeout or keep-alive interval was zero.
    #[error("timeout and keep-alive intervals must be greater than zero")]
    NonPositiveInterval,
}

/// A failure of a domain operation.
///
/// Every fallible [`Tree`](crate::Tree) method returns this. Callers match on
/// it: a [`CoreError::Validation`] belongs next to a form field, a
/// [`CoreError::Cycle`] belongs next to the drop target of a drag.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// A value the model refuses to hold.
    #[error(transparent)]
    Validation(#[from] ValidationError),

    /// The operation named a node the tree does not contain.
    #[error("no node with id {0}")]
    NodeNotFound(NodeId),

    /// The operation named a parent the tree does not contain.
    #[error("no parent node with id {0}")]
    ParentNotFound(NodeId),

    /// An insert used an id that is already taken.
    #[error("node {0} is already in the tree")]
    DuplicateNodeId(NodeId),

    /// Only folders hold children.
    #[error("node {0} cannot hold children; only folders can")]
    NotAContainer(NodeId),

    /// The move would have made a node its own ancestor.
    #[error("moving node {node} under {parent} would make it its own ancestor")]
    Cycle {
        /// The node being moved.
        node: NodeId,
        /// The proposed new parent.
        parent: NodeId,
    },

    /// The operation would have produced a tree deeper than
    /// [`MAX_TREE_DEPTH`].
    #[error("resulting tree depth is {depth}; the maximum is {max}", max = MAX_TREE_DEPTH)]
    DepthExceeded {
        /// The depth the operation would have produced.
        depth: usize,
    },

    /// An update changed `parent_id`.
    ///
    /// Re-parenting is a distinct operation because it re-resolves inheritance
    /// for the whole subtree, and the interface shows that diff before
    /// applying it. Letting an ordinary field edit move a node would make that
    /// change invisible.
    #[error("node {node} cannot be re-parented by an update; use move_node")]
    ParentChanged {
        /// The node whose update was rejected.
        node: NodeId,
    },

    /// The operation requires a connection node and was given another kind.
    #[error("node {0} is not a connection")]
    NotAConnection(NodeId),

    /// A parent walk did not terminate within the number of nodes in the tree.
    ///
    /// The mutating API cannot produce such a tree; this exists so that a tree
    /// built from an untrusted or corrupted store fails loudly instead of
    /// looping.
    #[error("the parent chain does not terminate; the tree is corrupt")]
    CorruptTree,
}
