//! Tests for the PuTTY session importer.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use remoter_core::{NodeRef, Tree};

use super::*;
use crate::preview::PreviewCredential;

/// What `reg export HKCU\Software\SimonTatham\PuTTY\Sessions` writes, trimmed
/// to the values that matter and a few of the ones PuTTY always adds.
const EXPORT: &str = r#"Windows Registry Editor Version 5.00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions]

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\Default%20Settings]
"HostName"=""
"Protocol"="ssh"
"PortNumber"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\web%2001]
"Present"=dword:00000001
"HostName"="web-01.example.com"
"Protocol"="ssh"
"PortNumber"=dword:000008ae
"UserName"="deploy"
"PublicKeyFile"="C:\\Users\\alex\\.ssh\\deploy.ppk"
"PortForwardings"="L8080=localhost:80,D1080"
"Compression"=dword:00000001
"TerminalType"="xterm"
"PingIntervalSecs"=dword:0000001e
"Font"="Consolas"
"Colour0"="187,187,187"
"Wordness0"=hex:00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
  00,00,00,00,00,00,00,00,00,00,00

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\bastion]
"HostName"="bastion.example.com"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"UserName"="jump"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\db]
"HostName"="root@db.internal"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"ProxyMethod"=dword:00000006
"ProxyHost"="bastion"
"ProxyPort"=dword:00000016

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\cache]
"HostName"="10.0.0.9"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"ProxyMethod"=dword:00000006
"ProxyHost"="gw.example.com"
"ProxyPort"=dword:00000898
"ProxyUsername"="tunnel"
"ProxyPassword"="tunnel-secret"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\switch]
"HostName"="192.0.2.1"
"Protocol"="telnet"
"PortNumber"=dword:00000017

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\console]
"HostName"=""
"Protocol"="serial"
"SerialLine"="COM1"

[HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\via%20socks]
"HostName"="app.example.com"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"ProxyMethod"=dword:00000002
"ProxyHost"="socks.example.com"
"ProxyPort"=dword:00000438
"ProxyPassword"="socks-secret"

[HKEY_CURRENT_USER\Software\9bis.com\KiTTY\Sessions\router]
"HostName"="[2001:db8::1]"
"Protocol"="ssh"
"PortNumber"=dword:00000016
"Folder"="Network/Core"
"#;

fn preview() -> ImportPreview {
    parse_reg(EXPORT.as_bytes(), &Limits::new()).unwrap()
}

fn node<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewNode {
    preview
        .nodes()
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name} in {:?}", preview.summaries()))
}

fn connection<'a>(preview: &'a ImportPreview, name: &str) -> &'a ConnectionProps {
    let PreviewKind::Connection(props) = &node(preview, name).kind else {
        panic!("{name} is not a connection");
    };
    props
}

fn credential_of<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewCredential {
    let Inherited::Explicit(reference) = &connection(preview, name).credential else {
        panic!("{name} has no credential of its own");
    };
    preview
        .nodes()
        .iter()
        .find_map(|node| match &node.kind {
            PreviewKind::Credential(credential) if node.id == reference.id() => Some(credential),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no credential for {name}"))
}

fn hop_of(preview: &ImportPreview, name: &str) -> NodeId {
    let Inherited::Explicit(chain) = &connection(preview, name).gateway else {
        panic!("{name} has no gateway");
    };
    let [hop] = chain.hops.as_slice() else {
        panic!("{name} has {} hops", chain.hops.len());
    };
    let NodeRef::Live(id) = hop.node else {
        panic!("{name}'s hop is not live");
    };
    id
}

#[test]
fn a_session_comes_in_with_its_account_key_and_port() {
    let preview = preview();
    let web = connection(&preview, "web 01");
    assert_eq!(web.protocol.as_str(), "ssh");
    assert_eq!(web.host, "web-01.example.com");
    assert_eq!(web.port, Inherited::Explicit(2222));
    assert_eq!(web.keepalive_secs, Inherited::Explicit(30));
    let account = credential_of(&preview, "web 01");
    assert_eq!(account.username, "deploy");
    assert_eq!(
        account.secret,
        PreviewSecret::Unsealed(SecretKind::External {
            provider: "putty-key-file".to_owned(),
            reference: "C:\\Users\\alex\\.ssh\\deploy.ppk".to_owned(),
        })
    );
}

#[test]
fn what_differs_from_puttys_defaults_is_kept_and_the_terminal_is_not() {
    let preview = preview();
    let web = node(&preview, "web 01");
    assert_eq!(
        web.custom_fields
            .get("putty.PortForwardings")
            .map(String::as_str),
        Some("L8080=localhost:80,D1080")
    );
    assert_eq!(
        web.custom_fields
            .get("putty.Compression")
            .map(String::as_str),
        Some("1")
    );
    // The default terminal type, the font and the colours say nothing about
    // the server.
    assert!(!web.custom_fields.contains_key("putty.TerminalType"));
    assert!(!web.custom_fields.keys().any(|key| key.contains("Font")));
    assert!(!web.custom_fields.keys().any(|key| key.contains("Colour")));
    // The port the protocol uses anyway is left to it.
    assert_eq!(connection(&preview, "bastion").port, Inherited::Inherit);
}

#[test]
fn the_default_settings_are_not_a_server() {
    let preview = preview();
    assert!(
        preview
            .nodes()
            .iter()
            .all(|node| node.name != "Default Settings")
    );
}

#[test]
fn a_proxy_naming_a_saved_session_becomes_a_gateway_through_it() {
    let preview = preview();
    assert_eq!(hop_of(&preview, "db"), node(&preview, "bastion").id);
    assert_eq!(credential_of(&preview, "db").username, "root");
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::GatewayMapped {
                item: "db".to_owned(),
                hops: 1,
            })
    );
}

#[test]
fn a_proxy_naming_a_machine_gets_a_jump_host_with_its_password() {
    let preview = preview();
    let hop = hop_of(&preview, "cache");
    let made = preview.nodes().iter().find(|node| node.id == hop).unwrap();
    assert_eq!(made.name, "gw.example.com");
    assert_eq!(made.parent_id, Some(node(&preview, "Jump hosts").id));
    let PreviewKind::Connection(props) = &made.kind else {
        panic!("the jump host is not a connection");
    };
    assert_eq!(props.port, Inherited::Explicit(2200));
    let account = credential_of(&preview, "gw.example.com");
    assert_eq!(account.username, "tunnel");
    let PreviewSecret::Password(password) = &account.secret else {
        panic!("the proxy password did not come across");
    };
    assert_eq!(password.expose(), "tunnel-secret");
    assert_eq!(preview.report().counts().secrets, 1);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretsRecovered { count: 1 })
    );
}

#[test]
fn a_proxy_remoter_cannot_use_is_reported_and_its_password_dropped() {
    let preview = preview();
    let findings = preview.report().findings();
    assert!(findings.contains(&Finding::ProxyNotSupported {
        item: "via socks".to_owned(),
        proxy: "socks5".to_owned(),
        host: "socks.example.com".to_owned(),
    }));
    assert!(findings.contains(&Finding::SecretNotMapped {
        item: "via socks".to_owned(),
        field: "ProxyPassword".to_owned(),
    }));
    let socks = node(&preview, "via socks");
    assert_eq!(
        socks
            .custom_fields
            .get("putty.ProxyHost")
            .map(String::as_str),
        Some("socks.example.com")
    );
    for node in preview.nodes() {
        for value in node.custom_fields.values() {
            assert!(!value.contains("secret"), "{} keeps a password", node.name);
        }
    }
    assert_eq!(
        connection(&preview, "via socks").gateway,
        Inherited::Inherit
    );
}

#[test]
fn other_protocols_keep_their_names_and_a_serial_line_is_left_out() {
    let preview = preview();
    let switch = connection(&preview, "switch");
    assert_eq!(switch.protocol.as_str(), "telnet");
    assert_eq!(switch.port, Inherited::Inherit);
    let findings = preview.report().findings();
    assert!(findings.contains(&Finding::UnknownProtocol {
        item: "switch".to_owned(),
        protocol: "telnet".to_owned(),
        mapped_to: "telnet".to_owned(),
    }));
    assert!(findings.contains(&Finding::SkippedItem {
        item: "console".to_owned(),
        reason: SkipReason::UnsupportedKind,
    }));
    assert_eq!(preview.report().counts().skipped, 1);
}

#[test]
fn kittys_sessions_and_folders_come_in_too() {
    let preview = preview();
    let router = node(&preview, "router");
    let core = node(&preview, "Core");
    assert_eq!(router.parent_id, Some(core.id));
    assert_eq!(core.parent_id, Some(node(&preview, "Network").id));
    assert_eq!(connection(&preview, "router").host, "[2001:db8::1]");
}

#[test]
fn the_preview_is_a_tree_the_domain_model_accepts() {
    let (nodes, _) = preview().into_parts();
    let built: Vec<_> = nodes
        .into_iter()
        .map(|node| {
            let sealed = node.holds_password().then(|| vec![1]);
            node.into_node(0, sealed).unwrap()
        })
        .collect();
    let tree = Tree::from_nodes(built).unwrap();
    assert!(tree.validate_all().is_empty());
}

#[test]
fn an_export_as_reg_writes_it_in_utf16_is_read_the_same() {
    let mut bytes = vec![0xff, 0xfe];
    for unit in EXPORT.replace('\n', "\r\n").encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    let preview = parse_reg(&bytes, &Limits::new()).unwrap();
    assert_eq!(
        connection(&preview, "web 01").port,
        Inherited::Explicit(2222)
    );
    assert!(looks_like_reg(&crate::xml::sniff_head(&bytes)));
}

#[test]
fn a_unix_session_file_is_read_by_its_name() {
    let file = "HostName=deploy@web-02.example.com\nProtocol=ssh\nPortNumber=2222\n\
PublicKeyFile=/home/alex/.ssh/deploy.ppk\nFont=server:fixed\n";
    let session = read_session_file(file.as_bytes(), "web%2002", &Limits::new()).unwrap();
    assert_eq!(session.name, "web 02");
    assert!(!format!("{session:?}").contains("deploy.ppk"));
    assert!(looks_like_session_file(file));
    let preview = parse_sessions(vec![session], &Limits::new()).unwrap();
    let web = connection(&preview, "web 02");
    assert_eq!(web.host, "web-02.example.com");
    assert_eq!(web.port, Inherited::Explicit(2222));
    assert_eq!(credential_of(&preview, "web 02").username, "deploy");
}

#[test]
fn a_file_is_read_as_whichever_of_the_two_it_is() {
    let from_export = parse_file(EXPORT.as_bytes(), "putty.reg", &Limits::new()).unwrap();
    assert!(from_export.nodes().len() > 5);
    let from_session = parse_file(
        b"HostName=solo.example.com\nProtocol=ssh\n",
        "solo",
        &Limits::new(),
    )
    .unwrap();
    assert_eq!(connection(&from_session, "solo").host, "solo.example.com");
    // A registry export of something else is refused, not read as a session.
    assert!(matches!(
        parse_file(
            b"Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Other]\n",
            "other.reg",
            &Limits::new()
        )
        .map(|preview| preview.nodes().len()),
        Ok(0)
    ));
}

#[test]
fn only_the_two_session_keys_are_ever_named_as_registry_paths() {
    assert_eq!(
        registry_key(r"HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions"),
        Some(REGISTRY_KEYS[0])
    );
    assert_eq!(
        registry_key(r"hkcu\software\9bis.com\kitty\sessions\"),
        Some(REGISTRY_KEYS[1])
    );
    assert_eq!(registry_key(r"HKEY_LOCAL_MACHINE\SAM\SAM"), None);
    assert_eq!(
        registry_key(r"HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\SshHostKeys"),
        None
    );
    assert_eq!(registry_key("/home/you/.putty/sessions"), None);
}

#[test]
fn a_sessions_directory_is_read_file_by_file_in_name_order() {
    let directory = std::env::temp_dir().join(format!(
        "remoter-putty-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos())
    ));
    std::fs::create_dir_all(directory.join("not-a-session")).unwrap();
    std::fs::write(
        directory.join("web%2002"),
        "HostName=web-02.example.com\nProtocol=ssh\n",
    )
    .unwrap();
    std::fs::write(
        directory.join("Default%20Settings"),
        "HostName=\nProtocol=ssh\n",
    )
    .unwrap();
    std::fs::write(directory.join("bastion"), "HostName=bastion.example.com\n").unwrap();

    let sessions = read_directory(&directory, &Limits::new()).unwrap();
    let names: Vec<&str> = sessions
        .iter()
        .map(|session| session.name.as_str())
        .collect();
    assert_eq!(names, ["Default Settings", "bastion", "web 02"]);
    let preview = parse_sessions(sessions, &Limits::new()).unwrap();
    assert_eq!(preview.report().counts().connections, 2);

    let limits = Limits {
        max_nodes: 2,
        ..Limits::new()
    };
    assert!(matches!(
        read_directory(&directory, &limits),
        Err(ImportError::TooManyItems { .. })
    ));
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(matches!(
        read_directory(&directory, &Limits::new()),
        Err(ImportError::ReadFailed {
            reason: ReadFailure::NotFound,
            ..
        })
    ));
}

#[test]
fn names_are_unescaped_the_way_putty_escaped_them() {
    assert_eq!(unescape_name("web%2001"), "web 01");
    assert_eq!(unescape_name("%2Ehidden"), ".hidden");
    assert_eq!(unescape_name("a%25b"), "a%b");
    assert_eq!(unescape_name("M%C3%BCnchen"), "München");
    // A code-page byte that is not UTF-8 is still a character.
    assert_eq!(unescape_name("M%FCnchen"), "München");
    assert_eq!(unescape_name("broken%2"), "broken%2");
    assert_eq!(unescape_name("broken%zz"), "broken%zz");
}

#[test]
fn detection_needs_both_the_header_and_a_session_key() {
    assert!(looks_like_reg(EXPORT));
    assert!(!looks_like_reg(
        "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\Other]\n"
    ));
    assert!(!looks_like_reg(
        "[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\a]\n"
    ));
    assert!(looks_like_reg(
        "REGEDIT4\n\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\a]\n"
    ));
    assert!(!looks_like_session_file("HostName=x\n"));
}

#[test]
fn something_that_is_not_an_export_is_refused() {
    assert!(matches!(
        parse_reg(b"Host web\n  HostName web.example.com\n", &Limits::new()),
        Err(ImportError::WrongFormat { .. })
    ));
}

#[test]
fn deleted_keys_and_unrelated_keys_are_not_sessions() {
    let export = "Windows Registry Editor Version 5.00\n\n\
[-HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\gone]\n\"HostName\"=\"gone.example.com\"\n\n\
[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\SshHostKeys]\n\"ssh-ed25519@22:x\"=\"0x1\"\n\n\
[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\kept\\Sub]\n\"HostName\"=\"sub.example.com\"\n";
    let preview = parse_reg(export.as_bytes(), &Limits::new()).unwrap();
    assert!(preview.nodes().is_empty(), "{:?}", preview.summaries());
}

#[test]
fn escapes_in_values_are_undone() {
    let export = "Windows Registry Editor Version 5.00\n\n\
[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\q]\n\
\"HostName\"=\"q.example.com\"\n\"RemoteCommand\"=\"echo \\\"hi\\\" \\\\ done\"\n";
    let preview = parse_reg(export.as_bytes(), &Limits::new()).unwrap();
    assert_eq!(
        node(&preview, "q")
            .custom_fields
            .get("putty.RemoteCommand")
            .map(String::as_str),
        Some("echo \"hi\" \\ done")
    );
}

#[test]
fn the_bounds_hold() {
    let limits = Limits {
        max_items: 4,
        ..Limits::small()
    };
    assert!(matches!(
        parse_reg(EXPORT.as_bytes(), &limits),
        Err(ImportError::TooManyItems { .. })
    ));
    let long = format!(
        "Windows Registry Editor Version 5.00\n\n[HKEY_CURRENT_USER\\Software\\SimonTatham\\PuTTY\\Sessions\\x]\n\"HostName\"=\"{}\"\n",
        "a".repeat(5000)
    );
    assert!(matches!(
        parse_reg(long.as_bytes(), &Limits::small()),
        Err(ImportError::ValueTooLong { .. })
    ));
}

#[test]
fn truncation_anywhere_is_never_a_panic() {
    for cut in 0..EXPORT.len() {
        if EXPORT.is_char_boundary(cut) {
            let _ = parse_reg(&EXPORT.as_bytes()[..cut], &Limits::new());
        }
    }
}
