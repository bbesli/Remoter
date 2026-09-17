//! Remote Desktop Connection's `.rdp` files.
//!
//! One file is one connection. The file is a list of `name:type:value` lines,
//! where the type is `s` for a string, `i` for an integer and `b` for binary
//! written as hex; Microsoft documents the properties in *Supported RDP
//! properties* (learn.microsoft.com/azure/virtual-desktop/rdp-properties).
//! `mstsc` saves the file as UTF-16 with a byte-order mark, which
//! [`as_text`] reads.
//!
//! | Property | Becomes |
//! |---|---|
//! | `full address` | The host, and the port when the address carries one. |
//! | `server port` | The port, when the address did not carry one and it is not 3389. |
//! | `username`, `domain` | The credential's account and domain. `DOMAIN\user` is split. |
//! | `password 51` | Nothing: see below. The credential asks for its password. |
//! | `desktopwidth`, `desktopheight` | The `desktop_width` and `desktop_height` settings. |
//! | `enablecredsspsupport:i:0` | `network_level_authentication` off. |
//! | `alternate shell`, `shell working directory` | The `alternate_shell` and `work_dir` settings. |
//! | `gatewayhostname` | A warning: this build has no Remote Desktop Gateway. |
//!
//! Every other property is kept verbatim in `custom_fields` under
//! `rdp.<property>`, spaces written as `_`. A property whose name mentions a
//! password is never kept anywhere: `custom_fields` is not an encrypted field.
//!
//! **A saved password does not come across.** `password 51` is a blob
//! encrypted with Windows data protection (`CryptProtectData`) to the Windows
//! account that saved it, and nothing but that account on that machine can
//! open it. The connection's credential is created with its account name and
//! no password, and asks for one the first time it is used; the report says so.

use std::collections::HashMap;

use remoter_core::{ConnectionProps, Inherited, ProtocolId, ProtocolSettings, validate_host};

use crate::error::ImportError;
use crate::limits::Limits;
use crate::mapping::{CredentialPool, clean_name, custom_key, preserve, split_address};
use crate::preview::{ImportPreview, PreviewBuilder, PreviewKind, PreviewNode, PreviewSecret};
use crate::report::{Finding, SkipReason, SourceFormat};
use crate::xml::as_text;

/// The adapter an `.rdp` file's connection uses.
const PROTOCOL: &str = "rdp";

/// The port Remote Desktop listens on unless told otherwise.
const DEFAULT_PORT: i64 = 3389;

/// The desktop sizes the RDP adapter's schema accepts, MS-RDPEDISP §2.2.2.2.1's
/// own bounds. A size outside them is kept as a custom field instead.
const DESKTOP_SIZE: core::ops::RangeInclusive<i64> = 200..=8192;

/// The longest shell or working directory the adapter's schema accepts.
const MAX_SHELL_CHARS: usize = 512;

/// The property holding the saved password.
const SAVED_PASSWORD: &str = "password 51";

/// One `name:type:value` line.
struct Property<'a> {
    /// Lower case, trimmed.
    name: String,
    value: &'a str,
}

/// Parses an `.rdp` file into the connection it describes.
///
/// `name` is what the connection is called — the file's name without its
/// extension, which is how Remote Desktop Connection itself lists one. The
/// host stands in when it is empty.
///
/// # Errors
///
/// [`ImportError::WrongFormat`] when no line of the file is a property, and the
/// usual bounded-parse refusals. A file with no usable address is a preview
/// with nothing in it and a finding that says why, not an error.
pub fn parse(bytes: &[u8], name: &str, limits: &Limits) -> Result<ImportPreview, ImportError> {
    let text = as_text(bytes, limits)?;
    let properties = read(&text, limits)?;
    if properties.is_empty() {
        return Err(ImportError::WrongFormat {
            expected: "a Remote Desktop Connection file",
        });
    }
    // The last spelling of a property wins, the way a reader that goes top to
    // bottom and overwrites would have it.
    let by_name: HashMap<&str, &str> = properties
        .iter()
        .map(|property| (property.name.as_str(), property.value))
        .collect();
    let get = |key: &str| by_name.get(key).map(|value| value.trim()).unwrap_or("");
    let integer = |key: &str| get(key).parse::<i64>().ok();

    let mut builder = PreviewBuilder::new(SourceFormat::RdpFile, *limits);
    let address = get("full address");
    let mut connection_name = clean_name(name);
    if connection_name.is_empty() {
        connection_name = clean_name(address);
    }

    let Some((host, port)) = split_address(address).filter(|(host, _)| validate_host(host).is_ok())
    else {
        builder.report_mut().counts_mut().skipped += 1;
        builder.report_mut().push(
            limits,
            Finding::SkippedItem {
                item: connection_name,
                reason: if address.is_empty() {
                    SkipReason::Empty
                } else {
                    SkipReason::UnusableHost
                },
            },
        );
        return Ok(builder.finish());
    };
    if connection_name.is_empty() {
        connection_name = clean_name(&host);
    }

    let protocol = ProtocolId::new(PROTOCOL)?;
    let mut props = ConnectionProps::new(PROTOCOL, host)?;
    let mut consumed: Vec<&str> = vec!["full address", "username", "domain", SAVED_PASSWORD];
    let server_port = integer("server port");
    props.port = match (port, server_port) {
        (Some(port), _) => Inherited::Explicit(port),
        (None, Some(port)) if port != DEFAULT_PORT => u16::try_from(port)
            .ok()
            .filter(|port| *port != 0)
            .map_or(Inherited::Inherit, Inherited::Explicit),
        _ => Inherited::Inherit,
    };
    // Read when the port now says what it said, or it said the default; a value
    // that is not a port at all is kept as it was written.
    if port.is_some() || server_port == Some(DEFAULT_PORT) || !props.port.is_inherit() {
        consumed.push("server port");
    }

    props.settings = settings(&get, &integer, &mut consumed)?;

    let mut credentials = CredentialPool::new("Imported credentials");
    let raw_user = get("username");
    let (domain, username) = match raw_user.split_once('\\') {
        Some((domain, user)) => (domain.trim(), user.trim()),
        None => (get("domain"), raw_user),
    };
    let saved = get(SAVED_PASSWORD);
    if !username.is_empty() || !domain.is_empty() || !saved.is_empty() {
        let secret = PreviewSecret::not_carried(saved.as_bytes());
        props.credential = Inherited::Explicit(credentials.intern(
            &mut builder,
            &connection_name,
            username.to_owned(),
            (!domain.is_empty()).then(|| domain.to_owned()),
            secret,
            vec![protocol],
        )?);
        if !saved.is_empty() {
            builder
                .report_mut()
                .push(limits, Finding::ProtectedPasswordsNotCarried { count: 1 });
        }
    }

    let gateway = get("gatewayhostname");
    // 0 is "do not use a gateway" and 4 "bypass it for local addresses", which
    // with nothing else set means the same; 1, 2 and 3 all put one in the way.
    if !gateway.is_empty() && !matches!(integer("gatewayusagemethod"), Some(0 | 4)) {
        builder.report_mut().push(
            limits,
            Finding::RdGatewayNotSupported {
                item: connection_name.clone(),
                host: clean_name(gateway),
            },
        );
    }

    let mut node = PreviewNode::new(
        remoter_core::NodeId::new(),
        connection_name.clone(),
        PreviewKind::Connection(props),
    );
    let mut kept = 0usize;
    let mut dropped = false;
    for property in &properties {
        let name = property.name.as_str();
        if consumed.contains(&name) {
            continue;
        }
        if name.contains("password") {
            if !property.value.trim().is_empty() {
                builder.report_mut().push(
                    limits,
                    Finding::SecretNotMapped {
                        item: connection_name.clone(),
                        field: clean_name(name),
                    },
                );
            }
            continue;
        }
        let Some(key) = custom_key("rdp", &name.replace(' ', "_")) else {
            continue;
        };
        if node.custom_fields.contains_key(&key) {
            // Kept once, the value the rest of the file was read with.
            continue;
        }
        let value = by_name.get(name).copied().unwrap_or(property.value);
        if preserve(
            &mut node,
            key,
            value.trim().to_owned(),
            limits.max_custom_fields,
        ) {
            kept += 1;
        } else {
            dropped = true;
        }
    }
    if kept > 0 {
        builder.report_mut().push(
            limits,
            Finding::SettingsPreserved {
                item: connection_name,
                count: kept,
            },
        );
    }
    if dropped {
        builder.report_mut().push(
            limits,
            Finding::LimitReached {
                limit: "custom_fields".to_owned(),
            },
        );
    }

    builder.push(node)?;
    credentials.finish(&mut builder);
    Ok(builder.finish())
}

/// The adapter settings the file sets, each only when the value is one the
/// adapter's schema accepts. What is taken is added to `consumed`, so the rest
/// is kept verbatim.
fn settings<'a>(
    get: &impl Fn(&str) -> &'a str,
    integer: &impl Fn(&str) -> Option<i64>,
    consumed: &mut Vec<&'static str>,
) -> Result<ProtocolSettings, ImportError> {
    let mut settings = ProtocolSettings::new();
    if let (Some(width), Some(height)) = (integer("desktopwidth"), integer("desktopheight")) {
        if DESKTOP_SIZE.contains(&width) && DESKTOP_SIZE.contains(&height) {
            settings.insert("desktop_width", width.to_string())?;
            settings.insert("desktop_height", height.to_string())?;
            consumed.extend(["desktopwidth", "desktopheight"]);
        }
    }
    match integer("enablecredsspsupport") {
        Some(0) => {
            settings.insert("network_level_authentication", "false")?;
            consumed.push("enablecredsspsupport");
        }
        // On is the adapter's default already; saying it again adds nothing.
        Some(1) => consumed.push("enablecredsspsupport"),
        _ => {}
    }
    for (property, setting) in [
        ("alternate shell", "alternate_shell"),
        ("shell working directory", "work_dir"),
    ] {
        let value = get(property);
        if value.is_empty() {
            consumed.push(property);
        } else if value.chars().count() <= MAX_SHELL_CHARS && !value.chars().any(char::is_control) {
            settings.insert(setting, value)?;
            consumed.push(property);
        }
    }
    Ok(settings)
}

/// The file's property lines, in order.
///
/// A line that is not `name:type:value` with a type of `s`, `i` or `b` is not a
/// property and is passed over: a file someone annotated by hand is still the
/// file it was.
fn read<'a>(text: &'a str, limits: &Limits) -> Result<Vec<Property<'a>>, ImportError> {
    let mut properties = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if index >= limits.max_items {
            return Err(ImportError::TooManyItems {
                limit: limits.max_items,
                unit: "lines",
            });
        }
        if line.len() > limits.max_value_bytes {
            return Err(ImportError::ValueTooLong {
                limit: limits.max_value_bytes,
                unit: "line",
            });
        }
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((kind, value)) = rest.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        if name.is_empty() || !matches!(kind.trim(), "s" | "i" | "b") {
            continue;
        }
        properties.push(Property { name, value });
    }
    Ok(properties)
}

/// Whether a document's head reads as an `.rdp` file: a `full address` property
/// among lines of the `name:type:value` shape.
pub(crate) fn looks_like(head: &str) -> bool {
    head.lines().any(|line| {
        let line = line.trim_start_matches('\u{feff}').trim_start();
        line.len() > 15
            && line
                .get(..15)
                .is_some_and(|start| start.eq_ignore_ascii_case("full address:s:"))
    })
}

#[cfg(test)]
#[allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]
mod tests {
    use remoter_core::SecretKind;

    use super::*;
    use crate::preview::PreviewCredential;

    /// What `mstsc` writes for a saved connection, trimmed to the properties
    /// that matter plus a few it always adds.
    const SAVED: &str = "screen mode id:i:2\r\n\
use multimon:i:0\r\n\
desktopwidth:i:1920\r\n\
desktopheight:i:1080\r\n\
session bpp:i:32\r\n\
full address:s:dc01.contoso.com:3390\r\n\
audiomode:i:0\r\n\
redirectclipboard:i:1\r\n\
authentication level:i:2\r\n\
prompt for credentials:i:0\r\n\
gatewayhostname:s:\r\n\
gatewayusagemethod:i:4\r\n\
enablecredsspsupport:i:1\r\n\
username:s:CONTOSO\\administrator\r\n\
password 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB\r\n";

    fn utf16(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xff, 0xfe];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn connection(preview: &ImportPreview) -> (&PreviewNode, &ConnectionProps) {
        preview
            .nodes()
            .iter()
            .find_map(|node| match &node.kind {
                PreviewKind::Connection(props) => Some((node, props)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no connection in {:?}", preview.summaries()))
    }

    fn credential(preview: &ImportPreview) -> &PreviewCredential {
        preview
            .nodes()
            .iter()
            .find_map(|node| match &node.kind {
                PreviewKind::Credential(credential) => Some(credential),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no credential in {:?}", preview.summaries()))
    }

    #[test]
    fn a_saved_connection_comes_in_as_mstsc_wrote_it() {
        let preview = parse(&utf16(SAVED), "Domain controller", &Limits::new()).unwrap();
        let (node, props) = connection(&preview);
        assert_eq!(node.name, "Domain controller");
        assert_eq!(props.protocol.as_str(), "rdp");
        assert_eq!(props.host, "dc01.contoso.com");
        assert_eq!(props.port, Inherited::Explicit(3390));
        assert_eq!(props.settings.get("desktop_width"), Some("1920"));
        assert_eq!(props.settings.get("desktop_height"), Some("1080"));
        assert_eq!(props.settings.get("network_level_authentication"), None);

        let account = credential(&preview);
        assert_eq!(account.username, "administrator");
        assert_eq!(account.domain.as_deref(), Some("CONTOSO"));
        assert!(matches!(
            account.secret,
            PreviewSecret::PasswordNotCarried(_)
        ));

        assert_eq!(
            node.custom_fields
                .get("rdp.redirectclipboard")
                .map(String::as_str),
            Some("1")
        );
        assert_eq!(
            node.custom_fields
                .get("rdp.screen_mode_id")
                .map(String::as_str),
            Some("2")
        );
        // The saved password is nowhere in the preview, not even as the blob.
        assert!(
            !node
                .custom_fields
                .iter()
                .any(|(key, value)| key.contains("password") || value.contains("D08C9DDF"))
        );
        let findings = preview.report().findings();
        assert!(findings.contains(&Finding::ProtectedPasswordsNotCarried { count: 1 }));
        assert!(
            !findings
                .iter()
                .any(|finding| matches!(finding, Finding::RdGatewayNotSupported { .. }))
        );
        assert_eq!(preview.report().counts().secrets, 0);
    }

    #[test]
    fn the_credential_becomes_a_password_credential_that_asks() {
        let preview = parse(SAVED.as_bytes(), "dc01", &Limits::new()).unwrap();
        let (nodes, _) = preview.into_parts();
        let credential = nodes
            .into_iter()
            .find(|node| matches!(node.kind, PreviewKind::Credential(_)))
            .unwrap();
        assert!(credential.holds_password());
        assert!(!credential.needs_sealing());
        assert!(!credential.summary().has_secret);
        let node = credential.into_node(0, Some(vec![0])).unwrap();
        assert!(matches!(
            node.kind,
            remoter_core::NodeKind::Credential(remoter_core::CredentialProps {
                secret: SecretKind::Password { .. },
                ..
            })
        ));
    }

    #[test]
    fn an_address_without_a_port_leaves_it_to_the_protocol() {
        let file = "full address:s:10.0.0.5\nserver port:i:3389\n";
        let preview = parse(file.as_bytes(), "", &Limits::new()).unwrap();
        let (node, props) = connection(&preview);
        assert_eq!(node.name, "10.0.0.5");
        assert_eq!(props.port, Inherited::Inherit);
        assert!(node.custom_fields.is_empty());
        assert!(preview.nodes().len() == 1, "no account, so no credential");

        let file = "full address:s:[2001:db8::7]\nserver port:i:3390\n";
        let preview = parse(file.as_bytes(), "v6", &Limits::new()).unwrap();
        let (_, props) = connection(&preview);
        assert_eq!(props.host, "[2001:db8::7]");
        assert_eq!(props.port, Inherited::Explicit(3390));
    }

    #[test]
    fn a_gateway_it_cannot_use_is_said_out_loud_and_kept() {
        let file =
            "full address:s:app01\ngatewayhostname:s:rdgw.contoso.com\ngatewayusagemethod:i:1\n";
        let preview = parse(file.as_bytes(), "app01", &Limits::new()).unwrap();
        assert!(
            preview
                .report()
                .findings()
                .contains(&Finding::RdGatewayNotSupported {
                    item: "app01".to_owned(),
                    host: "rdgw.contoso.com".to_owned(),
                })
        );
        let (node, _) = connection(&preview);
        assert_eq!(
            node.custom_fields
                .get("rdp.gatewayhostname")
                .map(String::as_str),
            Some("rdgw.contoso.com")
        );
    }

    #[test]
    fn settings_the_adapter_would_refuse_are_kept_rather_than_set() {
        let file = "full address:s:app01\ndesktopwidth:i:99999\ndesktopheight:i:1080\n\
enablecredsspsupport:i:0\nalternate shell:s:C:\\tools\\app.exe\nshell working directory:s:C:\\tools\n";
        let preview = parse(file.as_bytes(), "app01", &Limits::new()).unwrap();
        let (node, props) = connection(&preview);
        assert_eq!(props.settings.get("desktop_width"), None);
        assert_eq!(
            node.custom_fields
                .get("rdp.desktopwidth")
                .map(String::as_str),
            Some("99999")
        );
        assert_eq!(
            props.settings.get("network_level_authentication"),
            Some("false")
        );
        assert_eq!(
            props.settings.get("alternate_shell"),
            Some("C:\\tools\\app.exe")
        );
        assert_eq!(props.settings.get("work_dir"), Some("C:\\tools"));
    }

    #[test]
    fn a_password_in_any_other_property_is_dropped_and_reported() {
        let file = "full address:s:app01\nclear password:s:hunter2\n";
        let preview = parse(file.as_bytes(), "app01", &Limits::new()).unwrap();
        let (node, _) = connection(&preview);
        assert!(node.custom_fields.values().all(|value| value != "hunter2"));
        assert!(
            preview
                .report()
                .findings()
                .contains(&Finding::SecretNotMapped {
                    item: "app01".to_owned(),
                    field: "clear password".to_owned(),
                })
        );
    }

    #[test]
    fn a_file_with_no_usable_address_imports_nothing_and_says_why() {
        let preview = parse(b"full address:s:not a host\n", "broken", &Limits::new()).unwrap();
        assert!(preview.nodes().is_empty());
        assert_eq!(preview.report().counts().skipped, 1);
        assert!(preview.report().findings().contains(&Finding::SkippedItem {
            item: "broken".to_owned(),
            reason: SkipReason::UnusableHost,
        }));

        let preview = parse(b"screen mode id:i:2\n", "empty", &Limits::new()).unwrap();
        assert!(preview.nodes().is_empty());
    }

    #[test]
    fn something_that_is_not_an_rdp_file_is_refused() {
        assert!(matches!(
            parse(
                b"Host web\n  HostName web.example.com\n",
                "x",
                &Limits::new()
            ),
            Err(ImportError::WrongFormat { .. })
        ));
    }

    #[test]
    fn the_bounds_hold() {
        let limits = Limits {
            max_items: 3,
            ..Limits::small()
        };
        assert!(matches!(
            parse(b"a:s:1\nb:s:2\nc:s:3\nd:s:4\n", "x", &limits),
            Err(ImportError::TooManyItems { .. })
        ));
        let long = format!("full address:s:{}\n", "a".repeat(5000));
        assert!(matches!(
            parse(long.as_bytes(), "x", &Limits::small()),
            Err(ImportError::ValueTooLong { .. })
        ));
    }

    #[test]
    fn detection_reads_the_address_line() {
        assert!(looks_like("screen mode id:i:2\r\nfull address:s:dc01\r\n"));
        assert!(looks_like("\u{feff}Full Address:s:dc01"));
        assert!(!looks_like("Host dc01\n"));
        assert!(!looks_like("full address:s:"));
    }
}
