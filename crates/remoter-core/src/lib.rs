//! Domain model for Remoter: the connection tree, property inheritance and
//! validation.
//!
//! This crate is a leaf. It performs no I/O, holds no secrets and knows
//! nothing about cryptography, protocols or the interface. Everything in it is
//! a pure function of its inputs, which is what makes the inheritance
//! resolver exhaustively testable.
//!
//! See `docs/architecture/data-model.md` for the normative specification.

#![doc(html_no_source)]

mod error;
mod inherit;
mod node;
mod tree;
mod validate;

pub use error::{CoreError, ValidationError};
pub use inherit::{Inherited, Provenance, Resolved};
pub use node::{
    ConnectionProps, CredentialProps, CredentialRef, EffectiveConnection, FolderProps,
    GatewayChain, GatewayHop, GroupLayout, GroupProps, KeyFormat, Node, NodeId, NodeKind, NodeRef,
    ProtocolId, ProtocolSettings, ReconnectPolicy, RecordingPolicy, SecretKind, Tag,
};
pub use tree::{Tree, TreePatch, rekey};
pub use validate::{validate_host, validate_node, validate_port};

/// Maximum depth of the node tree. Deeper trees are rejected at validation.
pub const MAX_TREE_DEPTH: usize = 64;

/// Maximum number of hops in a gateway chain.
pub const MAX_GATEWAY_HOPS: usize = 8;

/// Maximum length of a node name, in characters.
pub const MAX_NAME_LEN: usize = 255;
