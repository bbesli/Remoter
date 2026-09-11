//! Value validation.
//!
//! These rules live here rather than in the interface so that the importers,
//! the CLI and the Tauri command surface all get the same guarantees the forms
//! do. An import of ten thousand mRemoteNG entries goes through exactly the
//! checks a typed-in connection does.
//!
//! Rules that need the whole tree — cycles, depth, credential purpose, gateway
//! hop targets — cannot be decided from one node and live on
//! [`Tree`](crate::Tree) instead.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::ValidationError;
use crate::inherit::Inherited;
use crate::node::{
    ConnectionProps, CredentialProps, FolderProps, GatewayChain, GroupLayout, GroupProps,
    MAX_DESCRIPTION_LEN, MAX_KEY_LEN, MAX_PROTOCOL_ID_LEN, MAX_TAG_LEN, MAX_USERNAME_LEN, Node,
    NodeKind, ProtocolSettings, ReconnectPolicy, SecretKind,
};
use crate::{MAX_GATEWAY_HOPS, MAX_NAME_LEN};

/// Maximum length of a DNS name, in characters. RFC 1035 §2.3.4 gives 255
/// octets for the wire form, which is 253 characters in presentation form.
const MAX_DNS_NAME_LEN: usize = 253;

/// Maximum length of one DNS label, in characters. RFC 1035 §2.3.4.
const MAX_DNS_LABEL_LEN: usize = 63;

/// Checks a node name.
///
/// # Errors
///
/// [`ValidationError::NameEmpty`], [`ValidationError::NameTooLong`] or
/// [`ValidationError::NameControlChar`].
pub(crate) fn validate_name(name: &str) -> Result<(), ValidationError> {
    if name.is_empty() {
        return Err(ValidationError::NameEmpty);
    }
    let len = name.chars().count();
    if len > MAX_NAME_LEN {
        return Err(ValidationError::NameTooLong { len });
    }
    if name.chars().any(char::is_control) {
        return Err(ValidationError::NameControlChar);
    }
    Ok(())
}

/// Checks that `host` is a DNS name, an IPv4 address, or a bracketed IPv6
/// address.
///
/// IPv6 must be bracketed. A bare `fe80::1` is ambiguous with a DNS name
/// containing colons in every place this string is later concatenated with a
/// port, and requiring the brackets at the edge means nothing downstream has to
/// guess.
///
/// # Errors
///
/// [`ValidationError::HostEmpty`] or [`ValidationError::InvalidHost`].
pub fn validate_host(host: &str) -> Result<(), ValidationError> {
    if host.is_empty() {
        return Err(ValidationError::HostEmpty);
    }
    let invalid = || ValidationError::InvalidHost {
        host: host.to_owned(),
    };

    if let Some(inner) = host.strip_prefix('[') {
        let Some(addr) = inner.strip_suffix(']') else {
            return Err(invalid());
        };
        // RFC 6874 permits a zone identifier on a link-local literal. The zone
        // is a local interface name, not part of the address, so it is split
        // off before parsing rather than rejected.
        let addr = addr.split_once('%').map_or(addr, |(a, _)| a);
        return addr.parse::<Ipv6Addr>().map(|_| ()).map_err(|_| invalid());
    }

    if host.parse::<Ipv4Addr>().is_ok() {
        return Ok(());
    }
    if host.contains(':') {
        // An unbracketed IPv6 literal, or something with a port glued on.
        return Err(invalid());
    }

    validate_dns_name(host).map_err(|()| invalid())
}

/// Checks presentation-form DNS syntax per RFC 1035 §2.3.1 with the RFC 1123
/// §2.1 relaxation that a label may start with a digit.
fn validate_dns_name(host: &str) -> Result<(), ()> {
    // A single trailing dot is the fully qualified form and is meaningful, not
    // a typo.
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.chars().count() > MAX_DNS_NAME_LEN {
        return Err(());
    }

    let mut last_label = "";
    for label in host.split('.') {
        if label.is_empty() || label.len() > MAX_DNS_LABEL_LEN {
            return Err(());
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(());
        }
        if label.starts_with('-') || label.ends_with('-') {
            return Err(());
        }
        last_label = label;
    }

    // RFC 1123 §2.1: the top-level component must not be all-numeric, which is
    // what keeps `10.0.0.256` from being accepted as a hostname after it fails
    // to parse as an address. A single all-numeric label is rejected for the
    // same reason.
    if last_label.bytes().all(|b| b.is_ascii_digit()) {
        return Err(());
    }
    Ok(())
}

/// Checks that a port is connectable.
///
/// # Errors
///
/// [`ValidationError::PortOutOfRange`] for port zero. The upper bound is
/// enforced by the type.
pub fn validate_port(port: u16) -> Result<(), ValidationError> {
    if port == 0 {
        return Err(ValidationError::PortOutOfRange);
    }
    Ok(())
}

/// Checks a tag.
pub(crate) fn validate_tag(tag: &str) -> Result<(), ValidationError> {
    let invalid = || ValidationError::InvalidTag {
        tag: tag.to_owned(),
    };
    if tag.is_empty() || tag.chars().count() > MAX_TAG_LEN {
        return Err(invalid());
    }
    if tag
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == ',')
    {
        return Err(invalid());
    }
    Ok(())
}

/// Checks a protocol identifier.
pub(crate) fn validate_protocol_id(id: &str) -> Result<(), ValidationError> {
    let invalid = || ValidationError::InvalidProtocolId { id: id.to_owned() };
    if id.is_empty() || id.chars().count() > MAX_PROTOCOL_ID_LEN {
        return Err(invalid());
    }
    if !id.bytes().all(|b| {
        b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_'
    }) {
        return Err(invalid());
    }
    if id.starts_with('.') || id.ends_with('.') {
        return Err(invalid());
    }
    Ok(())
}

/// Checks a protocol settings key.
pub(crate) fn validate_setting_key(key: &str) -> Result<(), ValidationError> {
    validate_key_syntax(key).map_err(|()| ValidationError::InvalidSettingKey {
        key: key.to_owned(),
    })
}

/// Checks a custom field key.
pub(crate) fn validate_custom_field_key(key: &str) -> Result<(), ValidationError> {
    validate_key_syntax(key).map_err(|()| ValidationError::InvalidCustomFieldKey {
        key: key.to_owned(),
    })
}

/// Shared syntax for the two key spaces: a namespaced identifier a plugin can
/// prefix without escaping.
fn validate_key_syntax(key: &str) -> Result<(), ()> {
    if key.is_empty() || key.chars().count() > MAX_KEY_LEN {
        return Err(());
    }
    if !key
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_')
    {
        return Err(());
    }
    if key.starts_with('.') || key.ends_with('.') {
        return Err(());
    }
    Ok(())
}

/// Checks a colour.
pub(crate) fn validate_colour(colour: &str) -> Result<(), ValidationError> {
    let invalid = || ValidationError::InvalidColour {
        colour: colour.to_owned(),
    };
    let Some(digits) = colour.strip_prefix('#') else {
        return Err(invalid());
    };
    if digits.len() != 6 && digits.len() != 8 {
        return Err(invalid());
    }
    if !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid());
    }
    Ok(())
}

/// Checks everything about a node that can be decided without the tree.
///
/// The tree-dependent rules — no cycles, depth, gateway hop targets,
/// credential purpose — are enforced by [`Tree`](crate::Tree), because a node
/// on its own cannot know them.
///
/// # Errors
///
/// The first [`ValidationError`] the node violates. Rules are checked in the
/// order the interface renders the fields, so the error points at the field
/// nearest the top of the form.
pub fn validate_node(node: &Node) -> Result<(), ValidationError> {
    validate_name(&node.name)?;

    let description_len = node.description.chars().count();
    if description_len > MAX_DESCRIPTION_LEN {
        return Err(ValidationError::DescriptionTooLong {
            len: description_len,
            max: MAX_DESCRIPTION_LEN,
        });
    }

    for tag in &node.tags {
        validate_tag(tag.as_str())?;
    }

    if let Some(icon) = &node.icon {
        if icon.is_empty() || icon.chars().any(char::is_control) {
            return Err(ValidationError::InvalidIcon);
        }
    }

    if let Some(colour) = &node.colour {
        validate_colour(colour)?;
    }

    for key in node.custom_fields.keys() {
        validate_custom_field_key(key)?;
    }

    match &node.kind {
        NodeKind::Folder(props) => validate_folder(props),
        NodeKind::Connection(props) => validate_connection(props),
        NodeKind::Credential(props) => validate_credential(props),
        NodeKind::Group(props) => validate_group(props),
        NodeKind::Separator => Ok(()),
    }
}

fn validate_folder(props: &FolderProps) -> Result<(), ValidationError> {
    validate_inherited_port(&props.port)?;
    validate_inherited_gateway(&props.gateway)?;
    validate_inherited_interval(&props.connect_timeout_ms)?;
    validate_inherited_interval(&props.keepalive_secs)?;
    validate_inherited_actions(&props.on_connect)?;
    validate_inherited_actions(&props.on_disconnect)?;
    validate_inherited_reconnect(&props.auto_reconnect)?;
    validate_settings(&props.settings)
}

fn validate_connection(props: &ConnectionProps) -> Result<(), ValidationError> {
    validate_host(&props.host)?;
    validate_inherited_port(&props.port)?;
    validate_inherited_gateway(&props.gateway)?;
    validate_inherited_interval(&props.connect_timeout_ms)?;
    validate_inherited_interval(&props.keepalive_secs)?;
    validate_inherited_actions(&props.on_connect)?;
    validate_inherited_actions(&props.on_disconnect)?;
    validate_inherited_reconnect(&props.auto_reconnect)?;
    validate_settings(&props.settings)
}

fn validate_credential(props: &CredentialProps) -> Result<(), ValidationError> {
    let len = props.username.chars().count();
    if len > MAX_USERNAME_LEN {
        return Err(ValidationError::UsernameTooLong {
            len,
            max: MAX_USERNAME_LEN,
        });
    }
    if props.username.chars().any(char::is_control) {
        return Err(ValidationError::IdentityControlChar);
    }
    if let Some(domain) = &props.domain {
        if domain.chars().any(char::is_control) {
            return Err(ValidationError::IdentityControlChar);
        }
    }
    validate_secret(&props.secret)
}

fn validate_secret(secret: &SecretKind) -> Result<(), ValidationError> {
    match secret {
        SecretKind::Password { sealed } => {
            if sealed.is_empty() {
                return Err(ValidationError::SealedMaterialEmpty);
            }
        }
        SecretKind::PrivateKey {
            sealed_key,
            sealed_passphrase,
            ..
        } => {
            if sealed_key.is_empty() || sealed_passphrase.as_ref().is_some_and(Vec::is_empty) {
                return Err(ValidationError::SealedMaterialEmpty);
            }
        }
        SecretKind::Certificate {
            sealed_cert,
            sealed_key,
        } => {
            if sealed_cert.is_empty() || sealed_key.is_empty() {
                return Err(ValidationError::SealedMaterialEmpty);
            }
        }
        SecretKind::External {
            provider,
            reference,
        } => {
            if provider.is_empty() || reference.is_empty() {
                return Err(ValidationError::ExternalCredentialIncomplete);
            }
        }
        // No material of its own: the agent holds the key.
        SecretKind::Agent { .. } => {}
    }
    Ok(())
}

fn validate_group(props: &GroupProps) -> Result<(), ValidationError> {
    if let GroupLayout::Grid { rows, cols } = props.layout {
        if rows == 0 || cols == 0 {
            return Err(ValidationError::InvalidLayout);
        }
    }
    Ok(())
}

fn validate_inherited_port(port: &Inherited<u16>) -> Result<(), ValidationError> {
    match port.explicit() {
        Some(p) => validate_port(*p),
        None => Ok(()),
    }
}

fn validate_inherited_interval(interval: &Inherited<u32>) -> Result<(), ValidationError> {
    match interval.explicit() {
        Some(0) => Err(ValidationError::NonPositiveInterval),
        _ => Ok(()),
    }
}

fn validate_inherited_actions(actions: &Inherited<Vec<String>>) -> Result<(), ValidationError> {
    let Some(actions) = actions.explicit() else {
        return Ok(());
    };
    if actions.iter().any(|a| a.trim().is_empty()) {
        return Err(ValidationError::EmptyAction);
    }
    Ok(())
}

fn validate_inherited_reconnect(
    policy: &Inherited<ReconnectPolicy>,
) -> Result<(), ValidationError> {
    let Some(ReconnectPolicy::Retry {
        max_attempts,
        initial_backoff_ms,
        max_backoff_ms,
    }) = policy.explicit()
    else {
        return Ok(());
    };
    if *max_attempts == 0 || *initial_backoff_ms == 0 || max_backoff_ms < initial_backoff_ms {
        return Err(ValidationError::InvalidReconnectPolicy);
    }
    Ok(())
}

fn validate_inherited_gateway(gateway: &Inherited<GatewayChain>) -> Result<(), ValidationError> {
    let Some(chain) = gateway.explicit() else {
        return Ok(());
    };
    validate_gateway_chain(chain)
}

/// Checks the length and internal uniqueness of a gateway chain.
///
/// Whether each hop exists and is a connection needs the tree, so
/// [`Tree::validate_references`](crate::Tree::validate_references) checks that.
pub(crate) fn validate_gateway_chain(chain: &GatewayChain) -> Result<(), ValidationError> {
    if chain.hops.len() > MAX_GATEWAY_HOPS {
        return Err(ValidationError::GatewayTooLong {
            hops: chain.hops.len(),
        });
    }
    // A chain that visits the same jump host twice is a loop in the tunnel,
    // not a longer route: the second hop would be dialled through itself.
    for (index, hop) in chain.hops.iter().enumerate() {
        if chain.hops[..index]
            .iter()
            .any(|h| h.node.id() == hop.node.id())
        {
            return Err(ValidationError::GatewayCycle { hop: hop.node.id() });
        }
    }
    Ok(())
}

fn validate_settings(settings: &ProtocolSettings) -> Result<(), ValidationError> {
    for (key, _) in settings.iter() {
        validate_setting_key(key)?;
    }
    Ok(())
}
