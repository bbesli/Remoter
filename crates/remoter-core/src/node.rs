//! Nodes: the things a user organises, and the properties they carry.
//!
//! Everything in the tree is a [`Node`]. What distinguishes a folder from a
//! connection from a credential is its [`NodeKind`], which owns the
//! kind-specific properties. Folders carry the same inheritable fields
//! connections do — that is the whole point of a folder here — so both
//! kinds expose them through the `*_field` accessors that the resolver walks.
//!
//! This module holds no secrets. Credential material arrives already sealed by
//! `remoter-vault` and is stored as opaque bytes that the domain model never
//! interprets, which is what keeps this crate free of any dependency on the
//! cryptography.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::ValidationError;
use crate::inherit::{Inherited, Provenance, Resolved};
use crate::validate::{validate_protocol_id, validate_setting_key, validate_tag};

/// Maximum length of a tag, in characters.
pub(crate) const MAX_TAG_LEN: usize = 64;

/// Maximum length of a protocol identifier, in characters.
pub(crate) const MAX_PROTOCOL_ID_LEN: usize = 64;

/// Maximum length of a settings or custom-field key, in characters.
pub(crate) const MAX_KEY_LEN: usize = 128;

/// Maximum length of a username, in characters.
///
/// Public because an importer has to refuse an account name this long before
/// it builds a preview on it: a preview the vault would reject at commit time
/// is a preview that lied to the user.
pub const MAX_USERNAME_LEN: usize = 255;

/// Maximum length of a node description, in characters.
pub(crate) const MAX_DESCRIPTION_LEN: usize = 4096;

/// A node's identity.
///
/// UUIDv7: time-ordered, so tree inserts stay index-friendly in SQLite, and
/// globally unique, so merging two vaults in some future release cannot
/// collide the way an autoincrement would.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(Uuid);

impl NodeId {
    /// Generates a fresh, time-ordered identity.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Wraps an existing UUID, for reading a node back out of storage.
    #[must_use]
    pub const fn from_uuid(uuid: Uuid) -> Self {
        Self(uuid)
    }

    /// The underlying UUID.
    #[must_use]
    pub const fn as_uuid(&self) -> &Uuid {
        &self.0
    }
}

impl Default for NodeId {
    fn default() -> Self {
        Self::new()
    }
}

impl From<Uuid> for NodeId {
    fn from(uuid: Uuid) -> Self {
        Self(uuid)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// A free-form label attached to a node.
///
/// Validated on construction and on deserialisation so that a hand-edited
/// export or a hostile import cannot introduce a tag the interface has to
/// defend against when it renders it.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Tag(String);

impl Tag {
    /// Validates and wraps a tag.
    ///
    /// # Errors
    ///
    /// [`ValidationError::InvalidTag`] if the tag is empty, longer than 64
    /// characters, or contains a control character or whitespace.
    pub fn new(tag: impl Into<String>) -> Result<Self, ValidationError> {
        let tag = tag.into();
        validate_tag(&tag)?;
        Ok(Self(tag))
    }

    /// The tag as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Tag {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<Tag> for String {
    fn from(tag: Tag) -> Self {
        tag.0
    }
}

impl fmt::Display for Tag {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The identifier of a protocol adapter: `ssh`, `rdp`, `vnc`, `sftp`, or a
/// plugin's namespaced id such as `vendor.x`.
///
/// A string rather than an enum because a plugin adds a protocol without a
/// schema migration, and the core must be able to hold a connection whose
/// adapter this build does not have.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ProtocolId(String);

impl ProtocolId {
    /// Validates and wraps a protocol identifier.
    ///
    /// # Errors
    ///
    /// [`ValidationError::InvalidProtocolId`] if the identifier is empty,
    /// longer than 64 characters, or contains anything but lowercase ASCII
    /// alphanumerics, `.`, `-` and `_`.
    pub fn new(id: impl Into<String>) -> Result<Self, ValidationError> {
        let id = id.into();
        validate_protocol_id(&id)?;
        Ok(Self(id))
    }

    /// The identifier as a string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The well-known default port for a built-in protocol.
    ///
    /// `None` for anything this build does not recognise — a plugin protocol
    /// supplies its own default through its adapter, which is the layer above
    /// this one. Returning `None` rather than guessing is what keeps
    /// [`EffectiveConnection::port`] honest about where the number came from.
    #[must_use]
    pub fn default_port(&self) -> Option<u16> {
        match self.0.as_str() {
            "ssh" | "sftp" => Some(22),
            "rdp" => Some(3389),
            "vnc" => Some(5900),
            "telnet" => Some(23),
            "http" => Some(80),
            "https" => Some(443),
            _ => None,
        }
    }
}

impl TryFrom<String> for ProtocolId {
    type Error = ValidationError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ProtocolId> for String {
    fn from(id: ProtocolId) -> Self {
        id.0
    }
}

impl fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A reference from one node to another.
///
/// Deleting a referenced node turns every reference to it into
/// [`NodeRef::Deleted`] rather than leaving a dangling id. A connection whose
/// credential was deleted then reports "credential deleted" instead of
/// silently falling back to whatever an ancestor happened to provide, which is
/// the failure mode that gets people logged in as the wrong user.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NodeRef {
    /// The target is present in this vault.
    Live(NodeId),
    /// The target was deleted. Its last known name is kept so the interface
    /// can name what is missing.
    Deleted {
        /// The id the reference used to resolve to.
        id: NodeId,
        /// The target's name at the time it was deleted.
        name: String,
    },
}

impl NodeRef {
    /// A reference to a live node.
    #[must_use]
    pub const fn live(id: NodeId) -> Self {
        Self::Live(id)
    }

    /// The referenced id, live or tombstoned.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        match self {
            Self::Live(id) | Self::Deleted { id, .. } => *id,
        }
    }

    /// Whether the target has been deleted.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        matches!(self, Self::Deleted { .. })
    }

    /// Points the reference at a node's new id, if `map` gives it one. A
    /// tombstone keeps its name; only the id it remembers changes.
    pub(crate) fn retarget(&mut self, map: &std::collections::HashMap<NodeId, NodeId>) {
        match self {
            Self::Live(id) | Self::Deleted { id, .. } => {
                if let Some(new) = map.get(id) {
                    *id = *new;
                }
            }
        }
    }

    /// Converts a live reference into a tombstone. Returns whether anything
    /// changed.
    pub(crate) fn tombstone(&mut self, name: &str) -> bool {
        match self {
            Self::Live(id) => {
                *self = Self::Deleted {
                    id: *id,
                    name: name.to_owned(),
                };
                true
            }
            Self::Deleted { .. } => false,
        }
    }
}

/// A reference to a credential node.
///
/// A distinct type from [`NodeRef`] so that a field which must point at a
/// credential cannot be handed a folder by a caller that got its arguments in
/// the wrong order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CredentialRef(NodeRef);

impl CredentialRef {
    /// A reference to a live credential.
    #[must_use]
    pub const fn live(id: NodeId) -> Self {
        Self(NodeRef::Live(id))
    }

    /// A reference to a credential that has since been deleted.
    #[must_use]
    pub fn deleted(id: NodeId, name: impl Into<String>) -> Self {
        Self(NodeRef::Deleted {
            id,
            name: name.into(),
        })
    }

    /// The referenced id, live or tombstoned.
    #[must_use]
    pub const fn id(&self) -> NodeId {
        self.0.id()
    }

    /// Whether the credential has been deleted.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        self.0.is_deleted()
    }

    /// The underlying reference.
    #[must_use]
    pub const fn as_node_ref(&self) -> &NodeRef {
        &self.0
    }

    pub(crate) fn tombstone(&mut self, name: &str) -> bool {
        self.0.tombstone(name)
    }

    pub(crate) const fn as_node_ref_mut(&mut self) -> &mut NodeRef {
        &mut self.0
    }
}

/// An ordered chain of gateway hops. Empty means a direct connection.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayChain {
    /// The hops, in the order they are traversed.
    pub hops: Vec<GatewayHop>,
}

impl GatewayChain {
    /// A direct connection.
    #[must_use]
    pub const fn direct() -> Self {
        Self { hops: Vec::new() }
    }

    /// Whether the connection is direct.
    #[must_use]
    pub fn is_direct(&self) -> bool {
        self.hops.is_empty()
    }

    /// The number of hops.
    #[must_use]
    pub fn len(&self) -> usize {
        self.hops.len()
    }

    /// Whether the chain has no hops.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.hops.is_empty()
    }
}

impl FromIterator<GatewayHop> for GatewayChain {
    fn from_iter<I: IntoIterator<Item = GatewayHop>>(iter: I) -> Self {
        Self {
            hops: iter.into_iter().collect(),
        }
    }
}

/// One hop in a gateway chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatewayHop {
    /// The connection node used as the gateway. Reusing a node rather than
    /// copying its host and port means a change to the jump host propagates to
    /// every chain that traverses it.
    pub node: NodeRef,
    /// The credential to authenticate this hop with; `None` uses the hop
    /// node's own resolved credential.
    pub credential: Option<CredentialRef>,
}

impl GatewayHop {
    /// A hop through `node`, authenticating with the hop node's own
    /// credential.
    #[must_use]
    pub const fn new(node: NodeId) -> Self {
        Self {
            node: NodeRef::Live(node),
            credential: None,
        }
    }

    /// A hop through `node`, authenticating with `credential`.
    #[must_use]
    pub const fn with_credential(node: NodeId, credential: CredentialRef) -> Self {
        Self {
            node: NodeRef::Live(node),
            credential: Some(credential),
        }
    }
}

/// Whether and how a session is recorded.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum RecordingPolicy {
    /// Never record.
    #[default]
    Never,
    /// Record only when the user asks, per session.
    OnRequest,
    /// Always record; the user cannot turn it off for this session.
    Always,
}

/// What to do when a session drops.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum ReconnectPolicy {
    /// Do not reconnect; report the drop.
    #[default]
    Never,
    /// Retry with exponential backoff.
    Retry {
        /// How many times to try before giving up.
        max_attempts: u32,
        /// The delay before the first retry, in milliseconds.
        initial_backoff_ms: u32,
        /// The ceiling the backoff grows to, in milliseconds.
        max_backoff_ms: u32,
    },
}

/// How a group arranges the sessions it opens.
#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub enum GroupLayout {
    /// One tab per member.
    #[default]
    Tabs,
    /// Split horizontally.
    SplitH,
    /// Split vertically.
    SplitV,
    /// A fixed grid.
    Grid {
        /// Number of rows.
        rows: u16,
        /// Number of columns.
        cols: u16,
    },
}

/// The on-disk format of a private key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum KeyFormat {
    /// OpenSSH's own `-----BEGIN OPENSSH PRIVATE KEY-----` container.
    OpenSsh,
    /// PKCS#8.
    Pkcs8,
    /// PuTTY's PPK.
    PuttyPpk,
}

/// A validated bag of protocol-specific settings.
///
/// A map rather than a fixed struct so that each adapter publishes a schema,
/// the interface renders its form from that schema, and a plugin protocol gets
/// exactly the same treatment as a built-in. Unknown keys are preserved
/// verbatim so that opening a vault in an older build does not silently
/// discard a newer protocol's settings.
///
/// Values are opaque strings here. Typing them against the adapter's schema
/// happens in the layer that owns the schema; the domain model validates only
/// the key syntax, which is what it can check without knowing the adapter.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    try_from = "BTreeMap<String, String>",
    into = "BTreeMap<String, String>"
)]
pub struct ProtocolSettings(BTreeMap<String, String>);

impl ProtocolSettings {
    /// An empty settings bag.
    #[must_use]
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Sets a key, returning the value it replaced.
    ///
    /// # Errors
    ///
    /// [`ValidationError::InvalidSettingKey`] if the key is empty, longer than
    /// 128 characters, or contains anything but ASCII alphanumerics, `.`, `-`
    /// and `_`.
    pub fn insert(
        &mut self,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Option<String>, ValidationError> {
        let key = key.into();
        validate_setting_key(&key)?;
        Ok(self.0.insert(key, value.into()))
    }

    /// Reads a key.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    /// Removes a key, returning its value.
    pub fn remove(&mut self, key: &str) -> Option<String> {
        self.0.remove(key)
    }

    /// Whether a key is set.
    #[must_use]
    pub fn contains_key(&self, key: &str) -> bool {
        self.0.contains_key(key)
    }

    /// The settings, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.0.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    /// The number of settings.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are no settings.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl TryFrom<BTreeMap<String, String>> for ProtocolSettings {
    type Error = ValidationError;

    fn try_from(map: BTreeMap<String, String>) -> Result<Self, Self::Error> {
        for key in map.keys() {
            validate_setting_key(key)?;
        }
        Ok(Self(map))
    }
}

impl From<ProtocolSettings> for BTreeMap<String, String> {
    fn from(settings: ProtocolSettings) -> Self {
        settings.0
    }
}

impl<'a> IntoIterator for &'a ProtocolSettings {
    type Item = (&'a str, &'a str);
    type IntoIter = Box<dyn Iterator<Item = (&'a str, &'a str)> + 'a>;

    fn into_iter(self) -> Self::IntoIter {
        Box::new(self.iter())
    }
}

/// How a credential's secret is held.
///
/// Every ciphertext here was produced by `remoter-vault` and is opaque to the
/// domain model: the nonce and algorithm live inside the sealed envelope, so
/// this crate needs no notion of an AEAD to carry it. `Debug` is implemented by
/// hand and redacts every one of these fields — the derive would put ciphertext
/// and lengths into any log line that formats a node.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretKind {
    /// A password, sealed.
    Password {
        /// The sealed password.
        sealed: Vec<u8>,
    },
    /// A private key, sealed, with an optional sealed passphrase.
    PrivateKey {
        /// The sealed private key.
        sealed_key: Vec<u8>,
        /// The sealed passphrase, if the key has one.
        sealed_passphrase: Option<Vec<u8>>,
        /// The key's container format.
        format: KeyFormat,
    },
    /// Delegated to the platform SSH agent. No key material is stored at all,
    /// which is the recommended option: the private key never enters this
    /// process's address space.
    Agent {
        /// Restricts which agent identity is used, by comment substring.
        comment_filter: Option<String>,
    },
    /// Delegated to an external provider through a plugin — HashiCorp Vault,
    /// Bitwarden, 1Password. The core does not know those products exist.
    External {
        /// The provider's identifier.
        provider: String,
        /// The provider-specific lookup reference.
        reference: String,
    },
    /// A certificate and its key, both sealed.
    Certificate {
        /// The sealed certificate.
        sealed_cert: Vec<u8>,
        /// The sealed key.
        sealed_key: Vec<u8>,
    },
}

impl fmt::Debug for SecretKind {
    /// Redacting. The variant is named because knowing whether a credential is
    /// agent-backed or password-backed is operationally useful and not secret;
    /// nothing else is printed, including lengths.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant = match self {
            Self::Password { .. } => "Password",
            Self::PrivateKey { .. } => "PrivateKey",
            Self::Agent { .. } => "Agent",
            Self::External { .. } => "External",
            Self::Certificate { .. } => "Certificate",
        };
        write!(f, "SecretKind::{variant}(<redacted>)")
    }
}

/// A folder: an organising node whose inheritable fields become the defaults
/// for everything beneath it.
///
/// The fields duplicate [`ConnectionProps`] deliberately. A folder that could
/// not hold a port or a gateway would not be able to do the one job it exists
/// for, and modelling "the inheritable set" as a shared struct would put a type
/// in the public API whose only purpose is to be flattened by serde.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FolderProps {
    /// Default credential for the subtree.
    pub credential: Inherited<CredentialRef>,
    /// Default gateway chain for the subtree.
    pub gateway: Inherited<GatewayChain>,
    /// Default port for the subtree.
    pub port: Inherited<u16>,
    /// Default connection timeout, in milliseconds.
    pub connect_timeout_ms: Inherited<u32>,
    /// Default keep-alive interval, in seconds.
    pub keepalive_secs: Inherited<u32>,
    /// Actions run after a session in the subtree connects.
    pub on_connect: Inherited<Vec<String>>,
    /// Actions run after a session in the subtree disconnects.
    pub on_disconnect: Inherited<Vec<String>>,
    /// Default recording policy for the subtree.
    pub recording: Inherited<RecordingPolicy>,
    /// Default reconnect policy for the subtree.
    pub auto_reconnect: Inherited<ReconnectPolicy>,
    /// Protocol settings that descendants merge under their own.
    pub settings: ProtocolSettings,
}

/// A connection: a named target and the settings to reach it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionProps {
    /// Which adapter speaks to this target.
    pub protocol: ProtocolId,
    /// The target host. Never inherited: inheriting a hostname would produce
    /// two nodes that silently point at the same machine.
    pub host: String,
    /// The port.
    pub port: Inherited<u16>,
    /// The credential to authenticate with.
    pub credential: Inherited<CredentialRef>,
    /// The gateway chain to traverse.
    pub gateway: Inherited<GatewayChain>,
    /// Adapter-specific settings, validated against the adapter's schema by
    /// the layer that owns the schema.
    pub settings: ProtocolSettings,
    /// Actions run after this session connects.
    pub on_connect: Inherited<Vec<String>>,
    /// Actions run after this session disconnects.
    pub on_disconnect: Inherited<Vec<String>>,
    /// Whether this session is recorded.
    pub recording: Inherited<RecordingPolicy>,
    /// What to do when this session drops.
    pub auto_reconnect: Inherited<ReconnectPolicy>,
    /// Connection timeout, in milliseconds.
    pub connect_timeout_ms: Inherited<u32>,
    /// Keep-alive interval, in seconds.
    pub keepalive_secs: Inherited<u32>,
}

impl ConnectionProps {
    /// A connection to `host` over `protocol`, with everything else inherited.
    ///
    /// # Errors
    ///
    /// [`ValidationError::InvalidProtocolId`] if `protocol` is not a valid
    /// protocol identifier. The host is not validated here; call
    /// [`validate_node`](crate::validate_node) or insert the node into a tree.
    pub fn new(
        protocol: impl Into<String>,
        host: impl Into<String>,
    ) -> Result<Self, ValidationError> {
        Ok(Self {
            protocol: ProtocolId::new(protocol)?,
            host: host.into(),
            port: Inherited::Inherit,
            credential: Inherited::Inherit,
            gateway: Inherited::Inherit,
            settings: ProtocolSettings::new(),
            on_connect: Inherited::Inherit,
            on_disconnect: Inherited::Inherit,
            recording: Inherited::Inherit,
            auto_reconnect: Inherited::Inherit,
            connect_timeout_ms: Inherited::Inherit,
            keepalive_secs: Inherited::Inherit,
        })
    }
}

/// A credential: a username and a sealed secret, organised in the tree and
/// inherited like any other property.
///
/// Credentials being nodes is what makes one service account shareable between
/// hundreds of connections without duplication. `Debug` is implemented by hand
/// so that formatting a node cannot print secret material.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialProps {
    /// The connection this credential belongs to, or `None` when it is a
    /// shared one the user organised in the tree themselves.
    ///
    /// Sharing one credential between two hundred connections is the feature
    /// that makes this application worth using at scale, and it must not become
    /// a tax on the person who has one server and a password. So typing a
    /// username and a password on a connection creates a credential *attached*
    /// to it: a real node with a real id — nothing else in the system needs a
    /// special case for it — that the interface presents as part of its
    /// connection rather than as a separate entry.
    ///
    /// An `Option<NodeId>` on the credential rather than a flag on the
    /// connection because the ownership is the credential's own property:
    /// [`Tree`](crate::Tree) has to answer "does this credential belong to
    /// somebody?" when deleting, moving and validating, and a flag on the other
    /// side of the reference would make that a search of the whole tree in
    /// every one of those places.
    ///
    /// `#[serde(default)]` because node properties are stored as a serialised
    /// map: a vault written before this field existed has no key for it, and
    /// must still load.
    #[serde(default)]
    pub attached_to: Option<NodeId>,
    /// The account name.
    pub username: String,
    /// The Windows or Kerberos domain, where the protocol has one.
    pub domain: Option<String>,
    /// The sealed secret.
    pub secret: SecretKind,
    /// Sealed TOTP configuration for keyboard-interactive second factors.
    /// Sealed because a TOTP URI contains the shared secret.
    pub totp: Option<Vec<u8>>,
    /// A rotation reminder, in milliseconds since the Unix epoch. Not
    /// enforced: refusing to connect with an expired credential would turn a
    /// hygiene prompt into an outage.
    pub expires_at: Option<i64>,
    /// Protocols this credential may be used with. Empty means unrestricted.
    ///
    /// This is the purpose restriction: a domain administrator credential
    /// scoped to `rdp` cannot be picked up by an SSH connection that inherited
    /// it from a shared parent folder.
    pub allowed_protocols: Vec<ProtocolId>,
}

impl CredentialProps {
    /// A shared credential for `username` holding `secret`, unrestricted in
    /// purpose.
    #[must_use]
    pub fn new(username: impl Into<String>, secret: SecretKind) -> Self {
        Self {
            attached_to: None,
            username: username.into(),
            domain: None,
            secret,
            totp: None,
            expires_at: None,
            allowed_protocols: Vec::new(),
        }
    }

    /// A credential belonging to one connection.
    ///
    /// This is what a username and a password typed on a connection become. It
    /// is a credential like any other; what `attached_to` adds is that it is
    /// deleted and moved with its connection, and that nothing else may point
    /// at it.
    #[must_use]
    pub fn attached(connection: NodeId, username: impl Into<String>, secret: SecretKind) -> Self {
        Self {
            attached_to: Some(connection),
            ..Self::new(username, secret)
        }
    }

    /// Whether this credential belongs to one connection rather than being
    /// shared.
    #[must_use]
    pub const fn is_attached(&self) -> bool {
        self.attached_to.is_some()
    }

    /// Whether this credential belongs to `connection`.
    #[must_use]
    pub fn belongs_to(&self, connection: NodeId) -> bool {
        self.attached_to == Some(connection)
    }

    /// Whether this credential may be used for `protocol`.
    #[must_use]
    pub fn permits(&self, protocol: &ProtocolId) -> bool {
        self.allowed_protocols.is_empty() || self.allowed_protocols.contains(protocol)
    }
}

impl fmt::Debug for CredentialProps {
    /// Redacting. Username and domain are printed because they are identifiers
    /// the user needs in a diagnostic and are not secret; the secret, the TOTP
    /// configuration and their presence-independent details are not.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialProps")
            .field("attached_to", &self.attached_to)
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("secret", &self.secret)
            .field("totp", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("allowed_protocols", &self.allowed_protocols)
            .finish()
    }
}

/// A group: opens several connections at once, into a chosen layout.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GroupProps {
    /// The connections to open.
    pub members: Vec<NodeRef>,
    /// How to arrange them.
    pub layout: GroupLayout,
    /// Send keystrokes to every terminal member at once.
    ///
    /// Off by default. The interface shows a persistent banner while it is
    /// active, because typing once into several production shells is exactly
    /// as useful and as dangerous as it sounds.
    pub broadcast: bool,
}

/// What a node is.
// The variants differ in size by more than clippy's threshold. Boxing the large
// ones would put an allocation behind every node in a tree the interface walks
// on every keystroke of the filter box, to save memory on separators, of which
// a vault holds a handful.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    /// An organising node. The only kind that holds children.
    Folder(FolderProps),
    /// A target to connect to.
    Connection(ConnectionProps),
    /// A username and a sealed secret.
    Credential(CredentialProps),
    /// Opens several connections at once.
    Group(GroupProps),
    /// A horizontal rule in the tree. Visual only.
    Separator,
}

impl NodeKind {
    /// An empty folder.
    #[must_use]
    pub fn folder() -> Self {
        Self::Folder(FolderProps::default())
    }

    /// A short, stable name for the kind, for diagnostics and telemetry that
    /// must not carry user content.
    #[must_use]
    pub const fn label(&self) -> &'static str {
        match self {
            Self::Folder(_) => "folder",
            Self::Connection(_) => "connection",
            Self::Credential(_) => "credential",
            Self::Group(_) => "group",
            Self::Separator => "separator",
        }
    }

    /// Whether this kind can hold children.
    #[must_use]
    pub const fn is_container(&self) -> bool {
        matches!(self, Self::Folder(_))
    }

    /// The connection properties, if this is a connection.
    #[must_use]
    pub const fn as_connection(&self) -> Option<&ConnectionProps> {
        match self {
            Self::Connection(props) => Some(props),
            _ => None,
        }
    }

    /// The credential properties, if this is a credential.
    #[must_use]
    pub const fn as_credential(&self) -> Option<&CredentialProps> {
        match self {
            Self::Credential(props) => Some(props),
            _ => None,
        }
    }

    /// The folder properties, if this is a folder.
    #[must_use]
    pub const fn as_folder(&self) -> Option<&FolderProps> {
        match self {
            Self::Folder(props) => Some(props),
            _ => None,
        }
    }

    /// The group properties, if this is a group.
    #[must_use]
    pub const fn as_group(&self) -> Option<&GroupProps> {
        match self {
            Self::Group(props) => Some(props),
            _ => None,
        }
    }
}

/// A node in the connection tree.
///
/// `parent_id` plus `sort_order` rather than a materialised path: moving a
/// subtree is then one row update instead of a rewrite of every descendant.
/// `revision` is monotonic from day one because it is bound into the AAD of
/// every encrypted secret field, which is what makes a rollback of a node
/// detectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Identity. UUIDv7.
    pub id: NodeId,
    /// The parent, or `None` for a root.
    pub parent_id: Option<NodeId>,
    /// Position among siblings. Ties break on id.
    pub sort_order: i64,
    /// What this node is, and its kind-specific properties.
    pub kind: NodeKind,
    /// Display name. Never inherited.
    pub name: String,
    /// Free-form notes.
    pub description: String,
    /// Labels for filtering and for policy — a `production` tag disables
    /// broadcast for groups beneath it.
    pub tags: Vec<Tag>,
    /// Icon reference. Resolved by nearest ancestor that sets one.
    pub icon: Option<String>,
    /// Accent colour, `#rrggbb` or `#rrggbbaa`. Resolved like the icon.
    pub colour: Option<String>,
    /// Creation time, in milliseconds since the Unix epoch.
    pub created_at: i64,
    /// Last modification time, in milliseconds since the Unix epoch.
    pub updated_at: i64,
    /// Monotonic revision. Bound into secret AAD.
    pub revision: u64,
    /// Asset tags, ticket references, rack positions, plugin data. Preserved
    /// verbatim on export and round-trip so that a newer build's data is not
    /// silently discarded by an older one.
    pub custom_fields: BTreeMap<String, String>,
    /// Soft-delete tombstone, in milliseconds since the Unix epoch.
    ///
    /// Deletion is soft because references to a deleted node become tombstones
    /// that still need a name to show, and because a synchronising vault has to
    /// be able to tell "deleted" from "never seen".
    pub deleted_at: Option<i64>,
}

impl Node {
    /// A root node of `kind` named `name`, created at `now`.
    ///
    /// `now` is a parameter rather than a call to the clock because this crate
    /// performs no I/O; the caller owns the clock, which is also what makes
    /// timestamps reproducible in tests.
    #[must_use]
    pub fn new(kind: NodeKind, name: impl Into<String>, now: i64) -> Self {
        Self::with_id(NodeId::new(), kind, name, now)
    }

    /// A node with a caller-supplied identity, for reading one back out of
    /// storage or for a deterministic test.
    #[must_use]
    pub fn with_id(id: NodeId, kind: NodeKind, name: impl Into<String>, now: i64) -> Self {
        Self {
            id,
            parent_id: None,
            sort_order: 0,
            kind,
            name: name.into(),
            description: String::new(),
            tags: Vec::new(),
            icon: None,
            colour: None,
            created_at: now,
            updated_at: now,
            revision: 1,
            custom_fields: BTreeMap::new(),
            deleted_at: None,
        }
    }

    /// Sets the parent and sort order. Builder sugar for constructing a tree
    /// in one expression; the tree itself still validates the placement.
    #[must_use]
    pub fn under(mut self, parent: NodeId, sort_order: i64) -> Self {
        self.parent_id = Some(parent);
        self.sort_order = sort_order;
        self
    }

    /// Whether this node has been soft-deleted.
    #[must_use]
    pub const fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Whether this node carries `tag`.
    #[must_use]
    pub fn has_tag(&self, tag: &str) -> bool {
        self.tags.iter().any(|t| t.as_str() == tag)
    }

    /// Bumps the revision and the modification time.
    pub fn touch(&mut self, now: i64) {
        self.revision = self.revision.saturating_add(1);
        self.updated_at = now;
    }

    /// The node's port field, if its kind has one.
    ///
    /// The `*_field` accessors exist so that the resolver is one function over
    /// all kinds. `None` means "this kind does not carry the field", which the
    /// resolver treats exactly like `Inherit`.
    #[must_use]
    pub const fn port_field(&self) -> Option<&Inherited<u16>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.port),
            NodeKind::Connection(c) => Some(&c.port),
            _ => None,
        }
    }

    /// The node's credential field, if its kind has one.
    #[must_use]
    pub const fn credential_field(&self) -> Option<&Inherited<CredentialRef>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.credential),
            NodeKind::Connection(c) => Some(&c.credential),
            _ => None,
        }
    }

    /// The node's gateway field, if its kind has one.
    #[must_use]
    pub const fn gateway_field(&self) -> Option<&Inherited<GatewayChain>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.gateway),
            NodeKind::Connection(c) => Some(&c.gateway),
            _ => None,
        }
    }

    /// The node's connection timeout field, if its kind has one.
    #[must_use]
    pub const fn connect_timeout_field(&self) -> Option<&Inherited<u32>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.connect_timeout_ms),
            NodeKind::Connection(c) => Some(&c.connect_timeout_ms),
            _ => None,
        }
    }

    /// The node's keep-alive field, if its kind has one.
    #[must_use]
    pub const fn keepalive_field(&self) -> Option<&Inherited<u32>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.keepalive_secs),
            NodeKind::Connection(c) => Some(&c.keepalive_secs),
            _ => None,
        }
    }

    /// The node's on-connect field, if its kind has one.
    #[must_use]
    pub const fn on_connect_field(&self) -> Option<&Inherited<Vec<String>>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.on_connect),
            NodeKind::Connection(c) => Some(&c.on_connect),
            _ => None,
        }
    }

    /// The node's on-disconnect field, if its kind has one.
    #[must_use]
    pub const fn on_disconnect_field(&self) -> Option<&Inherited<Vec<String>>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.on_disconnect),
            NodeKind::Connection(c) => Some(&c.on_disconnect),
            _ => None,
        }
    }

    /// The node's recording field, if its kind has one.
    #[must_use]
    pub const fn recording_field(&self) -> Option<&Inherited<RecordingPolicy>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.recording),
            NodeKind::Connection(c) => Some(&c.recording),
            _ => None,
        }
    }

    /// The node's reconnect field, if its kind has one.
    #[must_use]
    pub const fn auto_reconnect_field(&self) -> Option<&Inherited<ReconnectPolicy>> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.auto_reconnect),
            NodeKind::Connection(c) => Some(&c.auto_reconnect),
            _ => None,
        }
    }

    /// The node's protocol settings, if its kind has any.
    #[must_use]
    pub const fn settings_field(&self) -> Option<&ProtocolSettings> {
        match &self.kind {
            NodeKind::Folder(f) => Some(&f.settings),
            NodeKind::Connection(c) => Some(&c.settings),
            _ => None,
        }
    }

    /// The node's icon reference, if it sets one.
    #[must_use]
    pub const fn icon_field(&self) -> Option<&String> {
        self.icon.as_ref()
    }

    /// The node's colour, if it sets one.
    #[must_use]
    pub const fn colour_field(&self) -> Option<&String> {
        self.colour.as_ref()
    }

    /// Every reference this node holds to another: its credential, the hops
    /// of its gateway chain and their credentials, a group's members.
    ///
    /// Live and tombstoned alike. What is not a reference is not here: a
    /// credential's `attached_to` names its owner, which is a relationship the
    /// owner does not hold, and `parent_id` is the tree's.
    #[must_use]
    pub fn references(&self) -> Vec<&NodeRef> {
        let mut out = Vec::new();
        if let Some(Inherited::Explicit(credential)) = self.credential_field() {
            out.push(credential.as_node_ref());
        }
        if let Some(Inherited::Explicit(chain)) = self.gateway_field() {
            for hop in &chain.hops {
                out.push(&hop.node);
                if let Some(credential) = &hop.credential {
                    out.push(credential.as_node_ref());
                }
            }
        }
        if let NodeKind::Group(group) = &self.kind {
            out.extend(group.members.iter());
        }
        out
    }

    /// Turns every live reference whose target `keep` refuses into a
    /// tombstone, named by `name`. Returns how many it turned.
    ///
    /// For nodes arriving from somewhere else: a reference to a node that did
    /// not come with them, and is not in the tree they are joining, would
    /// otherwise be a dangling id that resolves to nothing and says nothing.
    /// A tombstone says what is missing.
    pub fn tombstone_references(
        &mut self,
        mut keep: impl FnMut(NodeId) -> bool,
        mut name: impl FnMut(NodeId) -> String,
    ) -> usize {
        let mut turned = 0;
        for reference in self.references_mut() {
            if !reference.is_deleted() && !keep(reference.id()) {
                let id = reference.id();
                if reference.tombstone(&name(id)) {
                    turned += 1;
                }
            }
        }
        turned
    }

    /// [`Node::references`], mutably.
    pub(crate) fn references_mut(&mut self) -> Vec<&mut NodeRef> {
        let mut out = Vec::new();
        let (credential, gateway) = match &mut self.kind {
            NodeKind::Folder(f) => (&mut f.credential, &mut f.gateway),
            NodeKind::Connection(c) => (&mut c.credential, &mut c.gateway),
            NodeKind::Group(group) => {
                out.extend(group.members.iter_mut());
                return out;
            }
            NodeKind::Credential(_) | NodeKind::Separator => return out,
        };
        if let Inherited::Explicit(credential) = credential {
            out.push(credential.as_node_ref_mut());
        }
        if let Inherited::Explicit(chain) = gateway {
            for hop in &mut chain.hops {
                out.push(&mut hop.node);
                if let Some(credential) = &mut hop.credential {
                    out.push(credential.as_node_ref_mut());
                }
            }
        }
        out
    }

    /// Whether two nodes differ in any field a descendant could inherit.
    ///
    /// Used to decide whether an edit needs to invalidate the subtree's
    /// resolution, so that an edit to a description does not make the
    /// interface re-render every descendant's effective values.
    pub(crate) fn inheritance_differs(&self, other: &Self) -> bool {
        self.port_field() != other.port_field()
            || self.credential_field() != other.credential_field()
            || self.gateway_field() != other.gateway_field()
            || self.connect_timeout_field() != other.connect_timeout_field()
            || self.keepalive_field() != other.keepalive_field()
            || self.on_connect_field() != other.on_connect_field()
            || self.on_disconnect_field() != other.on_disconnect_field()
            || self.recording_field() != other.recording_field()
            || self.auto_reconnect_field() != other.auto_reconnect_field()
            || self.settings_field() != other.settings_field()
            || self.icon != other.icon
            || self.colour != other.colour
    }
}

/// A connection with its inheritance flattened, and a provenance entry for
/// every field that came from somewhere.
///
/// This is what the session pipeline is handed, and what the connection editor
/// renders. Each `Resolved` field carries the node that supplied it, so the
/// interface can put "Inherited from 📁 Datacentre EU-West" next to the value
/// without walking the tree a second time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EffectiveConnection {
    /// The connection node this was resolved for.
    pub node: NodeId,
    /// The connection's name.
    pub name: String,
    /// The adapter to use.
    pub protocol: ProtocolId,
    /// The target host. Never inherited, so it carries no provenance.
    pub host: String,
    /// The port. `None` when nothing on the path set one and the protocol is
    /// not one this build knows a default for — the adapter supplies it then.
    pub port: Resolved<Option<u16>>,
    /// The credential, or `None` when nothing on the path supplied one. That
    /// case is allowed: the user is prompted at connect time.
    pub credential: Resolved<Option<CredentialRef>>,
    /// The account name, read from whichever credential resolved, and carrying
    /// that credential's provenance.
    ///
    /// A username is not stored on a connection — it belongs to a credential,
    /// which is what makes it shareable — so it resolves exactly as the
    /// credential does: `Own` when the credential is the connection's own
    /// (including one attached to it), `Ancestor` when it came from a folder.
    /// That is what lets the editor say "set on this connection" or "from
    /// 📁 Datacentre EU-West" next to the field the user typed in.
    pub username: Resolved<Option<String>>,
    /// Whether the resolved credential belongs to this connection alone.
    ///
    /// The editor shows a username and a secret inline when it does, and names
    /// the shared credential when it does not.
    pub credential_attached: bool,
    /// The gateway chain. Empty means direct.
    pub gateway: Resolved<GatewayChain>,
    /// Connection timeout in milliseconds, or `None` for the adapter's own.
    pub connect_timeout_ms: Resolved<Option<u32>>,
    /// Keep-alive interval in seconds, or `None` for the adapter's own.
    pub keepalive_secs: Resolved<Option<u32>>,
    /// Adapter settings, merged along the path with the nearest node winning
    /// per key, each carrying the node that supplied it.
    pub settings: BTreeMap<String, Resolved<String>>,
    /// Actions to run after connecting.
    pub on_connect: Resolved<Vec<String>>,
    /// Actions to run after disconnecting.
    pub on_disconnect: Resolved<Vec<String>>,
    /// Whether the session is recorded.
    pub recording: Resolved<RecordingPolicy>,
    /// What to do when the session drops.
    pub auto_reconnect: Resolved<ReconnectPolicy>,
    /// The icon to show.
    pub icon: Resolved<Option<String>>,
    /// The accent colour to use.
    pub colour: Resolved<Option<String>>,
}

impl EffectiveConnection {
    /// Every inheritable field, paired with where its value came from.
    ///
    /// Field names are stable ASCII identifiers, not translated strings: the
    /// interface maps them to a localised label, and a log line that carries
    /// one is readable in any locale.
    #[must_use]
    pub fn provenance(&self) -> Vec<(&'static str, Provenance)> {
        let mut out = vec![
            ("port", self.port.provenance),
            ("credential", self.credential.provenance),
            ("username", self.username.provenance),
            ("gateway", self.gateway.provenance),
            ("connect_timeout_ms", self.connect_timeout_ms.provenance),
            ("keepalive_secs", self.keepalive_secs.provenance),
            ("on_connect", self.on_connect.provenance),
            ("on_disconnect", self.on_disconnect.provenance),
            ("recording", self.recording.provenance),
            ("auto_reconnect", self.auto_reconnect.provenance),
            ("icon", self.icon.provenance),
            ("colour", self.colour.provenance),
        ];
        out.push(("settings", settings_provenance(&self.settings)));
        out
    }

    /// Whether any field on this connection was inherited from an ancestor.
    #[must_use]
    pub fn has_inherited_fields(&self) -> bool {
        self.provenance().iter().any(|(_, p)| p.is_inherited())
            || self.settings.values().any(Resolved::is_inherited)
    }
}

/// The coarsest provenance of the merged settings map: `Own` if any key was
/// set on the node itself, otherwise the nearest ancestor that contributed.
fn settings_provenance(settings: &BTreeMap<String, Resolved<String>>) -> Provenance {
    let mut coarse = Provenance::DefaultAtRoot;
    for resolved in settings.values() {
        match resolved.provenance {
            Provenance::Own(id) => return Provenance::Own(id),
            Provenance::Ancestor(id) => coarse = Provenance::Ancestor(id),
            Provenance::DefaultAt(_) | Provenance::DefaultAtRoot => {}
        }
    }
    coarse
}
