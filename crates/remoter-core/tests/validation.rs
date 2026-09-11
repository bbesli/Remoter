//! Every rule in the data model's validation table, in both directions.
//!
//! A rule that only has a rejecting test is half a rule: it passes just as
//! happily when the check is too strict as when it is correct. Each rule here
//! has at least one value it must accept and one it must reject, and the
//! boundary cases sit on the boundary.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use remoter_core::{
    ConnectionProps, CredentialProps, FolderProps, GatewayChain, GatewayHop, GroupLayout,
    GroupProps, Inherited, KeyFormat, MAX_GATEWAY_HOPS, MAX_NAME_LEN, Node, NodeId, NodeKind,
    NodeRef, ProtocolId, ProtocolSettings, ReconnectPolicy, SecretKind, Tag, ValidationError,
    validate_host, validate_node, validate_port,
};

const NOW: i64 = 1_760_000_000_000;

fn folder(name: &str) -> Node {
    Node::new(NodeKind::folder(), name, NOW)
}

fn connection(name: &str, host: &str) -> Node {
    Node::new(
        NodeKind::Connection(ConnectionProps::new("ssh", host).unwrap()),
        name,
        NOW,
    )
}

fn connection_props(node: &mut Node) -> &mut ConnectionProps {
    match &mut node.kind {
        NodeKind::Connection(props) => props,
        _ => panic!("not a connection"),
    }
}

fn folder_props(node: &mut Node) -> &mut FolderProps {
    match &mut node.kind {
        NodeKind::Folder(props) => props,
        _ => panic!("not a folder"),
    }
}

// --- names ---------------------------------------------------------------

#[test]
fn name_of_one_character_is_accepted() {
    assert!(validate_node(&folder("a")).is_ok());
}

#[test]
fn name_at_the_maximum_length_is_accepted() {
    let name = "a".repeat(MAX_NAME_LEN);
    assert!(validate_node(&folder(&name)).is_ok());
}

#[test]
fn empty_name_is_rejected() {
    assert_eq!(
        validate_node(&folder("")).unwrap_err(),
        ValidationError::NameEmpty
    );
}

#[test]
fn name_one_over_the_maximum_is_rejected() {
    let name = "a".repeat(MAX_NAME_LEN + 1);
    assert_eq!(
        validate_node(&folder(&name)).unwrap_err(),
        ValidationError::NameTooLong {
            len: MAX_NAME_LEN + 1
        }
    );
}

#[test]
fn name_length_is_counted_in_characters_not_bytes() {
    // 255 multi-byte characters is 255 characters, not 765 bytes' worth of
    // rejection. Importers of non-ASCII vaults depend on this.
    let name = "é".repeat(MAX_NAME_LEN);
    assert!(validate_node(&folder(&name)).is_ok());
}

#[test]
fn name_with_a_control_character_is_rejected() {
    assert_eq!(
        validate_node(&folder("web\u{7}01")).unwrap_err(),
        ValidationError::NameControlChar
    );
}

// --- hosts ---------------------------------------------------------------

#[test]
fn valid_hosts_are_accepted() {
    let accepted = [
        "db-primary",
        "localhost",
        "web-01.eu.acme.internal",
        "example.com.",
        "xn--bcher-kva.example",
        "a.b.c.d.e.f.g",
        "10.0.0.1",
        "255.255.255.255",
        "0.0.0.0",
        "[::1]",
        "[2001:db8::1]",
        "[fe80::1%eth0]",
        "9live.example",
    ];
    for host in accepted {
        assert!(
            validate_host(host).is_ok(),
            "expected `{host}` to be accepted, got {:?}",
            validate_host(host)
        );
    }
}

#[test]
fn invalid_hosts_are_rejected() {
    let rejected = [
        "-leading-hyphen.example",
        "trailing-hyphen-.example",
        "double..dot",
        "under_score.example",
        "space in name",
        "host:22",
        "::1",
        "fe80::1",
        "[::1",
        "::1]",
        "[not-an-address]",
        "10.0.0.256",
        "1.2.3.4.5",
        "192.168.0.1:8080",
        "café.example",
    ];
    for host in rejected {
        assert!(
            matches!(
                validate_host(host),
                Err(ValidationError::InvalidHost { .. })
            ),
            "expected `{host}` to be rejected, got {:?}",
            validate_host(host)
        );
    }
}

#[test]
fn empty_host_is_rejected() {
    assert_eq!(validate_host("").unwrap_err(), ValidationError::HostEmpty);
}

#[test]
fn dns_label_at_and_over_the_limit() {
    let label_63 = "a".repeat(63);
    assert!(validate_host(&format!("{label_63}.example")).is_ok());
    let label_64 = "a".repeat(64);
    assert!(validate_host(&format!("{label_64}.example")).is_err());
}

#[test]
fn dns_name_at_and_over_the_total_limit() {
    // Four labels of 63 plus three dots is 255, which is over the 253-character
    // presentation limit; dropping two characters brings it to 253.
    let long = [
        &"a".repeat(63),
        &"b".repeat(63),
        &"c".repeat(63),
        &"d".repeat(61),
    ]
    .map(String::as_str)
    .join(".");
    assert_eq!(long.chars().count(), 253);
    assert!(validate_host(&long).is_ok());
    assert!(validate_host(&format!("{long}x")).is_err());
}

#[test]
fn host_is_validated_through_the_node() {
    assert!(validate_node(&connection("web-01", "web-01.example")).is_ok());
    assert!(matches!(
        validate_node(&connection("web-01", "bad host")),
        Err(ValidationError::InvalidHost { .. })
    ));
}

// --- ports ---------------------------------------------------------------

#[test]
fn ports_in_range_are_accepted() {
    assert!(validate_port(1).is_ok());
    assert!(validate_port(22).is_ok());
    assert!(validate_port(u16::MAX).is_ok());
}

#[test]
fn port_zero_is_rejected() {
    assert_eq!(
        validate_port(0).unwrap_err(),
        ValidationError::PortOutOfRange
    );
}

#[test]
fn explicit_port_zero_is_rejected_through_the_node() {
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).port = Inherited::Explicit(0);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::PortOutOfRange
    );

    connection_props(&mut node).port = Inherited::Explicit(2222);
    assert!(validate_node(&node).is_ok());
}

#[test]
fn an_inherited_port_is_not_range_checked() {
    // There is nothing to check: the value will come from an ancestor that was
    // itself validated.
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).port = Inherited::Inherit;
    assert!(validate_node(&node).is_ok());
    connection_props(&mut node).port = Inherited::Default;
    assert!(validate_node(&node).is_ok());
}

// --- tags ----------------------------------------------------------------

#[test]
fn valid_tags_are_accepted() {
    for tag in [
        "production",
        "eu-west",
        "ticket:RM-42",
        "a".repeat(64).as_str(),
    ] {
        assert!(Tag::new(tag).is_ok(), "expected `{tag}` to be accepted");
    }
}

#[test]
fn invalid_tags_are_rejected() {
    for tag in ["", "with space", "with,comma", "with\ttab", &"a".repeat(65)] {
        assert!(
            matches!(Tag::new(tag), Err(ValidationError::InvalidTag { .. })),
            "expected `{tag}` to be rejected"
        );
    }
}

#[test]
fn tags_are_validated_through_the_node() {
    let mut node = folder("Datacentre");
    node.tags = vec![Tag::new("production").unwrap()];
    assert!(validate_node(&node).is_ok());
}

// --- protocol identifiers and settings keys ------------------------------

#[test]
fn valid_protocol_ids_are_accepted() {
    for id in ["ssh", "rdp", "vnc", "sftp", "vendor.x", "my_protocol-2"] {
        assert!(
            ProtocolId::new(id).is_ok(),
            "expected `{id}` to be accepted"
        );
    }
}

#[test]
fn invalid_protocol_ids_are_rejected() {
    for id in [
        "",
        "SSH",
        "with space",
        ".leading",
        "trailing.",
        &"a".repeat(65),
    ] {
        assert!(
            matches!(
                ProtocolId::new(id),
                Err(ValidationError::InvalidProtocolId { .. })
            ),
            "expected `{id}` to be rejected"
        );
    }
}

#[test]
fn well_known_protocols_have_default_ports() {
    assert_eq!(ProtocolId::new("ssh").unwrap().default_port(), Some(22));
    assert_eq!(ProtocolId::new("rdp").unwrap().default_port(), Some(3389));
    assert_eq!(ProtocolId::new("vnc").unwrap().default_port(), Some(5900));
    assert_eq!(ProtocolId::new("sftp").unwrap().default_port(), Some(22));
    // A plugin protocol supplies its own default through its adapter.
    assert_eq!(ProtocolId::new("vendor.x").unwrap().default_port(), None);
}

#[test]
fn settings_keys_are_validated_and_the_offending_key_is_named() {
    let mut settings = ProtocolSettings::new();
    assert!(settings.insert("terminal.type", "xterm-256color").is_ok());
    assert!(settings.insert("colour_depth-32", "32").is_ok());

    let error = settings.insert("bad key", "value").unwrap_err();
    assert_eq!(
        error,
        ValidationError::InvalidSettingKey {
            key: "bad key".to_owned()
        }
    );
    // The rejection names the key, never the value.
    assert!(error.to_string().contains("bad key"));
    assert!(!error.to_string().contains("value"));
}

#[test]
fn settings_round_trip_unknown_keys_verbatim() {
    let mut settings = ProtocolSettings::new();
    settings.insert("future.protocol.knob", "17").unwrap();
    let json = serde_json::to_string(&settings).unwrap();
    let back: ProtocolSettings = serde_json::from_str(&json).unwrap();
    assert_eq!(back.get("future.protocol.knob"), Some("17"));
}

#[test]
fn a_settings_key_rejected_on_deserialisation() {
    let json = r#"{"bad key":"value"}"#;
    assert!(serde_json::from_str::<ProtocolSettings>(json).is_err());
}

// --- colours, icons, custom fields, descriptions -------------------------

#[test]
fn colours_are_accepted_and_rejected() {
    let mut node = folder("Datacentre");
    for colour in ["#ff0000", "#FF0000", "#ff0000aa"] {
        node.colour = Some(colour.to_owned());
        assert!(validate_node(&node).is_ok(), "expected `{colour}` accepted");
    }
    for colour in ["ff0000", "#ff00", "#ff0000a", "#gggggg", ""] {
        node.colour = Some(colour.to_owned());
        assert!(
            matches!(
                validate_node(&node),
                Err(ValidationError::InvalidColour { .. })
            ),
            "expected `{colour}` rejected"
        );
    }
}

#[test]
fn icons_are_accepted_and_rejected() {
    let mut node = folder("Datacentre");
    node.icon = Some("lucide:server".to_owned());
    assert!(validate_node(&node).is_ok());
    node.icon = Some(String::new());
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::InvalidIcon
    );
    node.icon = Some("bad\u{1}icon".to_owned());
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::InvalidIcon
    );
}

#[test]
fn custom_field_keys_are_accepted_and_rejected() {
    let mut node = folder("Datacentre");
    node.custom_fields
        .insert("asset.tag".to_owned(), "RM-42".to_owned());
    assert!(validate_node(&node).is_ok());

    node.custom_fields
        .insert("bad key".to_owned(), "value".to_owned());
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::InvalidCustomFieldKey {
            key: "bad key".to_owned()
        }
    );
}

#[test]
fn an_over_long_description_is_rejected() {
    let mut node = folder("Datacentre");
    node.description = "a".repeat(4096);
    assert!(validate_node(&node).is_ok());
    node.description = "a".repeat(4097);
    assert!(matches!(
        validate_node(&node),
        Err(ValidationError::DescriptionTooLong { len: 4097, .. })
    ));
}

// --- gateway chains ------------------------------------------------------

fn chain_of(len: usize) -> GatewayChain {
    (0..len).map(|_| GatewayHop::new(NodeId::new())).collect()
}

#[test]
fn a_gateway_chain_at_the_hop_limit_is_accepted() {
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).gateway = Inherited::Explicit(chain_of(MAX_GATEWAY_HOPS));
    assert!(validate_node(&node).is_ok());
}

#[test]
fn a_gateway_chain_one_over_the_hop_limit_is_rejected() {
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).gateway = Inherited::Explicit(chain_of(MAX_GATEWAY_HOPS + 1));
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::GatewayTooLong {
            hops: MAX_GATEWAY_HOPS + 1
        }
    );
}

#[test]
fn a_gateway_chain_that_visits_a_hop_twice_is_rejected() {
    let repeated = NodeId::new();
    let chain: GatewayChain = vec![
        GatewayHop::new(NodeId::new()),
        GatewayHop::new(repeated),
        GatewayHop::new(NodeId::new()),
        GatewayHop::new(repeated),
    ]
    .into_iter()
    .collect();

    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).gateway = Inherited::Explicit(chain);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::GatewayCycle { hop: repeated }
    );
}

#[test]
fn an_empty_gateway_chain_means_direct() {
    let chain = GatewayChain::direct();
    assert!(chain.is_direct());
    assert_eq!(chain.len(), 0);

    let mut node = folder("Datacentre");
    folder_props(&mut node).gateway = Inherited::Explicit(chain);
    assert!(validate_node(&node).is_ok());
}

// --- intervals, actions and reconnect policies ---------------------------

#[test]
fn a_zero_interval_is_rejected_and_a_positive_one_accepted() {
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).connect_timeout_ms = Inherited::Explicit(0);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::NonPositiveInterval
    );
    connection_props(&mut node).connect_timeout_ms = Inherited::Explicit(15_000);
    assert!(validate_node(&node).is_ok());

    connection_props(&mut node).keepalive_secs = Inherited::Explicit(0);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::NonPositiveInterval
    );
    connection_props(&mut node).keepalive_secs = Inherited::Explicit(30);
    assert!(validate_node(&node).is_ok());
}

#[test]
fn an_empty_action_is_rejected() {
    let mut node = connection("web-01", "web-01.example");
    connection_props(&mut node).on_connect = Inherited::Explicit(vec!["tmux attach".to_owned()]);
    assert!(validate_node(&node).is_ok());

    connection_props(&mut node).on_connect = Inherited::Explicit(vec!["   ".to_owned()]);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::EmptyAction
    );

    connection_props(&mut node).on_connect = Inherited::Inherit;
    connection_props(&mut node).on_disconnect = Inherited::Explicit(vec![String::new()]);
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::EmptyAction
    );
}

#[test]
fn reconnect_policies_are_checked_for_coherence() {
    let mut node = connection("web-01", "web-01.example");

    connection_props(&mut node).auto_reconnect = Inherited::Explicit(ReconnectPolicy::Retry {
        max_attempts: 5,
        initial_backoff_ms: 500,
        max_backoff_ms: 30_000,
    });
    assert!(validate_node(&node).is_ok());

    for bad in [
        ReconnectPolicy::Retry {
            max_attempts: 0,
            initial_backoff_ms: 500,
            max_backoff_ms: 30_000,
        },
        ReconnectPolicy::Retry {
            max_attempts: 5,
            initial_backoff_ms: 0,
            max_backoff_ms: 30_000,
        },
        ReconnectPolicy::Retry {
            max_attempts: 5,
            initial_backoff_ms: 30_000,
            max_backoff_ms: 500,
        },
    ] {
        connection_props(&mut node).auto_reconnect = Inherited::Explicit(bad);
        assert_eq!(
            validate_node(&node).unwrap_err(),
            ValidationError::InvalidReconnectPolicy
        );
    }

    connection_props(&mut node).auto_reconnect = Inherited::Explicit(ReconnectPolicy::Never);
    assert!(validate_node(&node).is_ok());
}

// --- credentials ---------------------------------------------------------

fn password_credential(username: &str) -> Node {
    Node::new(
        NodeKind::Credential(CredentialProps::new(
            username,
            SecretKind::Password {
                sealed: vec![1, 2, 3],
            },
        )),
        "svc-deploy",
        NOW,
    )
}

#[test]
fn a_well_formed_credential_is_accepted() {
    assert!(validate_node(&password_credential("svc-deploy")).is_ok());
}

#[test]
fn an_over_long_username_is_rejected() {
    let node = password_credential(&"a".repeat(255));
    assert!(validate_node(&node).is_ok());
    let node = password_credential(&"a".repeat(256));
    assert!(matches!(
        validate_node(&node),
        Err(ValidationError::UsernameTooLong { len: 256, .. })
    ));
}

#[test]
fn a_control_character_in_an_identity_is_rejected() {
    let node = password_credential("svc\u{1}deploy");
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::IdentityControlChar
    );

    let mut node = password_credential("svc-deploy");
    if let NodeKind::Credential(props) = &mut node.kind {
        props.domain = Some("CONTOSO\u{1}".to_owned());
    }
    assert_eq!(
        validate_node(&node).unwrap_err(),
        ValidationError::IdentityControlChar
    );
}

#[test]
fn empty_sealed_material_is_rejected() {
    let cases = [
        SecretKind::Password { sealed: Vec::new() },
        SecretKind::PrivateKey {
            sealed_key: Vec::new(),
            sealed_passphrase: None,
            format: KeyFormat::OpenSsh,
        },
        SecretKind::PrivateKey {
            sealed_key: vec![1],
            sealed_passphrase: Some(Vec::new()),
            format: KeyFormat::Pkcs8,
        },
        SecretKind::Certificate {
            sealed_cert: Vec::new(),
            sealed_key: vec![1],
        },
        SecretKind::Certificate {
            sealed_cert: vec![1],
            sealed_key: Vec::new(),
        },
    ];
    for secret in cases {
        let node = Node::new(
            NodeKind::Credential(CredentialProps::new("svc", secret)),
            "svc",
            NOW,
        );
        assert_eq!(
            validate_node(&node).unwrap_err(),
            ValidationError::SealedMaterialEmpty
        );
    }
}

#[test]
fn an_agent_credential_needs_no_material() {
    let node = Node::new(
        NodeKind::Credential(CredentialProps::new(
            "svc-deploy",
            SecretKind::Agent {
                comment_filter: Some("deploy".to_owned()),
            },
        )),
        "svc-deploy",
        NOW,
    );
    assert!(validate_node(&node).is_ok());
}

#[test]
fn an_external_credential_needs_a_provider_and_a_reference() {
    for (provider, reference) in [("", "secret/deploy"), ("vault", ""), ("", "")] {
        let node = Node::new(
            NodeKind::Credential(CredentialProps::new(
                "svc",
                SecretKind::External {
                    provider: provider.to_owned(),
                    reference: reference.to_owned(),
                },
            )),
            "svc",
            NOW,
        );
        assert_eq!(
            validate_node(&node).unwrap_err(),
            ValidationError::ExternalCredentialIncomplete
        );
    }

    let node = Node::new(
        NodeKind::Credential(CredentialProps::new(
            "svc",
            SecretKind::External {
                provider: "vault".to_owned(),
                reference: "secret/deploy".to_owned(),
            },
        )),
        "svc",
        NOW,
    );
    assert!(validate_node(&node).is_ok());
}

#[test]
fn a_credential_never_formats_its_secret() {
    // Long enough that its rendered form cannot occur by accident, and made of
    // values whose decimal spellings are three digits — an earlier version of
    // this test searched for "91" and "92" (0x5b, 0x5c) and failed whenever the
    // node's randomly generated UUIDv7 happened to contain those two digits
    // side by side. It failed while the redaction was working perfectly, which
    // is the worst way for a security test to fail: the quickest way to make it
    // pass is to delete the assertion it trips on.
    let sealed = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    let totp = vec![0xd0, 0xd0, 0xca, 0xca, 0xfa, 0xce];

    let mut props = CredentialProps::new(
        "svc-deploy",
        SecretKind::Password {
            sealed: sealed.clone(),
        },
    );
    props.totp = Some(totp.clone());
    let node = Node::new(NodeKind::Credential(props), "svc-deploy", NOW);

    // A node is formatted into diagnostics; nothing sealed may survive that.
    let rendered = format!("{node:?}");
    assert!(rendered.contains("redacted"), "{rendered}");

    // Whole sequences, not individual numbers. A single byte's decimal spelling
    // collides with anything; the full rendering of the vector does not.
    for material in [&sealed, &totp] {
        let debug_form = format!("{material:?}");
        assert!(
            !rendered.contains(&debug_form),
            "sealed bytes leaked: {rendered}"
        );
        let joined = material
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        assert!(
            !rendered.contains(&joined),
            "sealed bytes leaked as hex: {rendered}"
        );
    }
}

// --- groups --------------------------------------------------------------

#[test]
fn a_grid_layout_needs_a_row_and_a_column() {
    let mut props = GroupProps {
        members: vec![NodeRef::live(NodeId::new())],
        layout: GroupLayout::Grid { rows: 2, cols: 3 },
        broadcast: false,
    };
    let node = Node::new(NodeKind::Group(props.clone()), "Web tier", NOW);
    assert!(validate_node(&node).is_ok());

    for layout in [
        GroupLayout::Grid { rows: 0, cols: 3 },
        GroupLayout::Grid { rows: 2, cols: 0 },
    ] {
        props.layout = layout;
        let node = Node::new(NodeKind::Group(props.clone()), "Web tier", NOW);
        assert_eq!(
            validate_node(&node).unwrap_err(),
            ValidationError::InvalidLayout
        );
    }
}

#[test]
fn broadcast_is_off_by_default() {
    assert!(!GroupProps::default().broadcast);
}

// --- separators ----------------------------------------------------------

#[test]
fn a_separator_still_needs_a_name() {
    assert!(validate_node(&Node::new(NodeKind::Separator, "———", NOW)).is_ok());
    assert_eq!(
        validate_node(&Node::new(NodeKind::Separator, "", NOW)).unwrap_err(),
        ValidationError::NameEmpty
    );
}

// --- serialisation round trip -------------------------------------------

#[test]
fn a_node_round_trips_through_json() {
    let mut node = connection("web-01", "web-01.eu.acme.internal");
    node.tags = vec![Tag::new("production").unwrap()];
    node.colour = Some("#00aa55".to_owned());
    node.custom_fields
        .insert("rack".to_owned(), "B12".to_owned());
    connection_props(&mut node).port = Inherited::Explicit(2222);

    let json = serde_json::to_string(&node).unwrap();
    let back: Node = serde_json::from_str(&json).unwrap();
    assert_eq!(node, back);
}
