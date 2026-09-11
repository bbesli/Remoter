//! Tests for the OpenSSH config importer.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use std::path::Path;

use remoter_core::{Node, Tree};

use super::*;
use crate::preview::PreviewKind as Kind;
use crate::report::Severity;

/// The config an administrator with a bastion actually has.
const ESTATE: &str = r#"
Host bastion
    HostName bastion.eu.acme.internal
    Port 2222
    IdentityFile ~/.ssh/id_ed25519

Host web-01 web-02
    HostName %h.eu.acme.internal
    ProxyJump bastion

Host db-primary
    HostName db-primary.eu.acme.internal
    User dba
    ProxyJump ops@bastion:2222,db-hop.eu.acme.internal

Host *.customer.example
    Port 2200

Host legacy
    HostName legacy.eu.acme.internal
    ProxyCommand ssh -q -W %h:%p bastion

Host oddball
    HostName oddball.eu.acme.internal
    ProxyCommand /usr/local/bin/corkscrew proxy 8080 %h %p

Match exec "test -f /tmp/on-vpn"
    Port 22022

# Last, because `ssh` keeps the first value it obtains: a universal block at
# the top of a file overrides everything below it.
Host *
    User svc-deploy
    ServerAliveInterval 30
    ConnectTimeout 10
    HashKnownHosts yes
"#;

fn preview_of(config: &str) -> ImportPreview {
    parse(config.as_bytes(), &Limits::new()).unwrap()
}

fn find<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewNode {
    preview
        .nodes()
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name}"))
}

fn connection<'a>(preview: &'a ImportPreview, name: &str) -> &'a ConnectionProps {
    let Kind::Connection(props) = &find(preview, name).kind else {
        panic!("{name} is not a connection");
    };
    props
}

#[test]
fn every_literal_host_becomes_a_connection_and_wildcards_do_not() {
    let preview = preview_of(ESTATE);
    let names: Vec<&str> = preview
        .nodes()
        .iter()
        .filter(|node| matches!(node.kind, Kind::Connection(_)))
        .map(|node| node.name.as_str())
        .collect();
    for expected in [
        "bastion",
        "web-01",
        "web-02",
        "db-primary",
        "legacy",
        "oddball",
    ] {
        assert!(names.contains(&expected), "{expected} is missing");
    }
    // `Host *` and `Host *.customer.example` name no machine.
    assert!(!names.contains(&"*"));
    assert!(!names.contains(&"*.customer.example"));
}

#[test]
fn the_universal_block_becomes_a_folder_that_everything_inherits_from() {
    let preview = preview_of(ESTATE);
    let Kind::Folder(defaults) = &find(&preview, "ssh_config defaults").kind else {
        panic!("the Host * block must become a folder");
    };
    assert_eq!(defaults.keepalive_secs, Inherited::Explicit(30));
    assert_eq!(defaults.connect_timeout_ms, Inherited::Explicit(10_000));
    assert_eq!(
        defaults.settings.len(),
        0,
        "options with no schema go to custom_fields, not settings"
    );

    let folder = find(&preview, "ssh_config defaults").id;
    assert_eq!(find(&preview, "web-01").parent_id, Some(folder));

    // A value that came only from `Host *` is not repeated on the connection.
    let web01 = connection(&preview, "web-01");
    assert_eq!(web01.keepalive_secs, Inherited::Inherit);
    assert_eq!(web01.connect_timeout_ms, Inherited::Inherit);
    assert_eq!(web01.credential, Inherited::Inherit);
}

#[test]
fn a_narrower_block_overrides_the_universal_one_explicitly() {
    let preview = preview_of(ESTATE);
    // `Host bastion` sets its own port; `Host *` sets none.
    assert_eq!(
        connection(&preview, "bastion").port,
        Inherited::Explicit(2222)
    );
    assert_eq!(connection(&preview, "web-01").port, Inherited::Inherit);
    // `Host db-primary` overrides the universal `User`.
    assert!(connection(&preview, "db-primary").credential.is_explicit());
}

#[test]
fn the_h_token_in_a_hostname_expands_to_the_alias() {
    let preview = preview_of(ESTATE);
    assert_eq!(
        connection(&preview, "web-01").host,
        "web-01.eu.acme.internal"
    );
    assert_eq!(
        connection(&preview, "web-02").host,
        "web-02.eu.acme.internal"
    );
}

#[test]
fn proxy_jump_becomes_a_gateway_chain_that_references_the_bastion_node() {
    let preview = preview_of(ESTATE);
    let bastion = find(&preview, "bastion").id;
    let Inherited::Explicit(chain) = &connection(&preview, "web-01").gateway else {
        panic!("web-01 must have a gateway chain");
    };
    assert_eq!(chain.hops.len(), 1);
    assert_eq!(chain.hops[0].node.id(), bastion);
    // The hop is a reference, not a copy: editing the bastion changes the route.
    assert!(!chain.hops[0].node.is_deleted());
}

#[test]
fn a_multi_hop_proxy_jump_keeps_the_order_ssh_traverses_it() {
    let preview = preview_of(ESTATE);
    let Inherited::Explicit(chain) = &connection(&preview, "db-primary").gateway else {
        panic!("db-primary must have a gateway chain");
    };
    assert_eq!(chain.hops.len(), 2);
    let bastion = find(&preview, "bastion").id;
    assert_eq!(chain.hops[0].node.id(), bastion);

    // The second hop is not a `Host` block, so a connection was made for it.
    let hop = preview
        .nodes()
        .iter()
        .find(|node| node.id == chain.hops[1].node.id())
        .unwrap();
    assert_eq!(hop.name, "db-hop.eu.acme.internal");
    assert_eq!(hop.parent_id, Some(find(&preview, "Jump hosts").id));
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::GatewaySynthesised {
                item: "db-primary".to_owned(),
                target: "db-hop.eu.acme.internal".to_owned()
            })
    );
}

#[test]
fn the_two_bastion_proxy_command_idioms_are_recognised() {
    let preview = preview_of(ESTATE);
    let bastion = find(&preview, "bastion").id;
    let Inherited::Explicit(chain) = &connection(&preview, "legacy").gateway else {
        panic!("the -W idiom must become a gateway chain");
    };
    assert_eq!(chain.hops[0].node.id(), bastion);

    let netcat = preview_of(
        "Host bastion\n  HostName b.example.com\n\
         Host web\n  HostName w.example.com\n  ProxyCommand ssh -q bastion nc %h %p\n",
    );
    let Inherited::Explicit(chain) = &connection(&netcat, "web").gateway else {
        panic!("the netcat idiom must become a gateway chain");
    };
    assert_eq!(chain.hops[0].node.id(), find(&netcat, "bastion").id);
}

#[test]
fn a_proxy_command_that_is_not_a_bastion_is_preserved_verbatim_and_flagged() {
    let preview = preview_of(ESTATE);
    let oddball = find(&preview, "oddball");
    assert_eq!(
        oddball
            .custom_fields
            .get("openssh.proxycommand")
            .map(String::as_str),
        Some("/usr/local/bin/corkscrew proxy 8080 %h %p")
    );
    let Kind::Connection(props) = &oddball.kind else {
        panic!("oddball must be a connection");
    };
    assert_eq!(props.gateway, Inherited::Inherit);
    assert!(preview.report().findings().iter().any(|finding| matches!(
        finding,
        Finding::UnmappedProxyCommand { item, .. } if item == "oddball"
    )));
}

#[test]
fn proxy_jump_none_pins_a_direct_connection_rather_than_inheriting_one() {
    // `Host *` goes last, because `ssh` takes the first value it obtains and a
    // universal block at the top of a file wins over everything below it.
    let preview = preview_of(
        "Host bastion\n  HostName b.example.com\n\
         Host direct\n  HostName d.example.com\n  ProxyJump none\n\
         Host *\n  ProxyJump bastion\n",
    );
    assert_eq!(
        connection(&preview, "direct").gateway,
        Inherited::Default,
        "`ProxyJump none` must stop the walk, not defer to the parent"
    );
}

#[test]
fn a_match_block_is_read_and_reported_but_not_applied() {
    let preview = preview_of(ESTATE);
    assert!(preview.report().findings().iter().any(|finding| matches!(
        finding,
        Finding::MatchBlockNotApplied { criteria, options }
            if criteria.contains("exec") && *options == 1
    )));
    // The Match block's port reached nothing.
    for node in preview.nodes() {
        if let Kind::Connection(props) = &node.kind {
            assert_ne!(props.port, Inherited::Explicit(22022));
        }
    }
}

#[test]
fn a_wildcard_block_is_folded_into_the_hosts_it_matches_and_named() {
    let preview = preview_of(
        "Host *.customer.example\n  Port 2200\n\
         Host a.customer.example\n  HostName a.customer.example\n\
         Host b.internal\n  HostName b.internal.example.com\n",
    );
    assert_eq!(
        connection(&preview, "a.customer.example").port,
        Inherited::Explicit(2200)
    );
    assert_eq!(connection(&preview, "b.internal").port, Inherited::Inherit);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::PatternBlockApplied {
                pattern: "*.customer.example".to_owned(),
                connections: 1
            })
    );
}

#[test]
fn an_identity_file_becomes_a_reference_and_the_key_is_not_read() {
    let preview = preview_of(ESTATE);
    let Inherited::Explicit(reference) = &connection(&preview, "bastion").credential else {
        panic!("bastion must reference a credential");
    };
    let Kind::Credential(credential) = &preview
        .nodes()
        .iter()
        .find(|node| node.id == reference.id())
        .unwrap()
        .kind
    else {
        panic!("the reference must point at a credential");
    };
    assert_eq!(credential.username, "svc-deploy");
    assert_eq!(
        credential.secret,
        PreviewSecret::Unsealed(SecretKind::External {
            provider: "openssh-identity-file".to_owned(),
            reference: "~/.ssh/id_ed25519".to_owned(),
        })
    );
    // Nothing was sealed, because nothing secret came across.
    assert_eq!(preview.report().counts().secrets, 0);
    assert_eq!(
        credential
            .allowed_protocols
            .iter()
            .map(ProtocolId::as_str)
            .collect::<Vec<_>>(),
        ["ssh"]
    );
}

#[test]
fn a_user_with_no_key_delegates_to_the_agent() {
    let preview = preview_of("Host a\n  HostName a.example.com\n  User root\n");
    let Inherited::Explicit(reference) = &connection(&preview, "a").credential else {
        panic!("a must reference a credential");
    };
    let Kind::Credential(credential) = &preview
        .nodes()
        .iter()
        .find(|node| node.id == reference.id())
        .unwrap()
        .kind
    else {
        panic!("the reference must point at a credential");
    };
    assert_eq!(
        credential.secret,
        PreviewSecret::Unsealed(SecretKind::Agent {
            comment_filter: None
        })
    );
}

#[test]
fn options_with_no_home_in_the_model_are_preserved_under_their_own_namespace() {
    let preview = preview_of(
        "Host a\n  HostName a.example.com\n  Compression yes\n  \
         LocalForward 8080 localhost:80\n  LocalForward 9090 localhost:90\n",
    );
    let node = find(&preview, "a");
    assert_eq!(
        node.custom_fields
            .get("openssh.compression")
            .map(String::as_str),
        Some("yes")
    );
    assert_eq!(
        node.custom_fields
            .get("openssh.localforward")
            .map(String::as_str),
        Some("8080 localhost:80\n9090 localhost:90")
    );
    assert!(preview.report().findings().iter().any(|finding| matches!(
        finding,
        Finding::SettingsPreserved { item, .. } if item == "a"
    )));
}

#[test]
fn a_host_the_domain_model_will_not_accept_is_skipped_and_named() {
    let preview = preview_of("Host broken\n  HostName not a hostname\n");
    assert_eq!(preview.report().counts().connections, 0);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "broken".to_owned(),
        reason: SkipReason::UnusableHost
    }));
    assert!(preview.report().needs_attention());
}

#[test]
fn includes_are_followed_and_splice_into_the_block_that_named_them() {
    let files = MemoryConfigFiles::new("/home/a/.ssh")
        .with(
            "/home/a/.ssh/config",
            "Host *\n  User svc\nInclude conf.d/*.conf\n",
        )
        .with(
            "/home/a/.ssh/conf.d/10-web.conf",
            "Host web-01\n  HostName web-01.example.com\n",
        )
        .with(
            "/home/a/.ssh/conf.d/20-db.conf",
            "Host db-01\n  HostName db-01.example.com\n",
        );
    let preview = parse_files(Path::new("/home/a/.ssh/config"), &files, &Limits::new()).unwrap();
    assert_eq!(preview.report().counts().connections, 2);
    assert_eq!(connection(&preview, "web-01").host, "web-01.example.com");
    assert_eq!(connection(&preview, "db-01").host, "db-01.example.com");
    // The `Host *` block that preceded the include is still the folder.
    assert_eq!(
        find(&preview, "web-01").parent_id,
        Some(find(&preview, "ssh_config defaults").id)
    );
}

#[test]
fn an_include_cycle_is_stopped_by_the_depth_limit() {
    let files = MemoryConfigFiles::new("/c")
        .with("/c/a", "Include b\n")
        .with("/c/b", "Include a\n");
    let limits = Limits {
        max_include_depth: 4,
        ..Limits::new()
    };
    let Err(err) = parse_files(Path::new("/c/a"), &files, &limits) else {
        panic!("an include cycle must be refused");
    };
    assert!(matches!(
        err,
        ImportError::IncludeTooDeep { .. } | ImportError::TooManyItems { .. }
    ));
}

#[test]
fn an_include_naming_a_missing_file_says_which_one() {
    let files = MemoryConfigFiles::new("/c").with("/c/config", "Include missing.conf\n");
    let Err(ImportError::ReadFailed { path, .. }) =
        parse_files(Path::new("/c/config"), &files, &Limits::new())
    else {
        panic!("expected a read failure naming the file");
    };
    assert_eq!(path, "/c/missing.conf");
}

#[test]
fn the_fuzzable_entry_point_never_reaches_the_filesystem() {
    // `Include` is a directive `parse` knows the name of and does nothing with,
    // which is what makes it safe to hand arbitrary bytes.
    let preview = preview_of("Include /etc/shadow\nHost a\n  HostName a.example.com\n");
    assert_eq!(preview.report().counts().connections, 1);
}

#[test]
fn the_preview_becomes_a_tree_the_domain_model_accepts() {
    let preview = preview_of(ESTATE);
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| node.into_node(1_700_000_000_000, None).unwrap())
        .collect();
    let tree = Tree::from_nodes(nodes).unwrap();
    assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());

    let web01 = tree
        .nodes()
        .find(|node| node.name == "web-01")
        .map(|node| node.id)
        .unwrap();
    let effective = tree.effective_connection(web01).unwrap();
    // The keep-alive came from the folder the `Host *` block became.
    assert_eq!(effective.keepalive_secs.value, Some(30));
    assert!(effective.keepalive_secs.is_inherited());
    // And the gateway is one hop through the bastion.
    assert_eq!(effective.gateway.value.hops.len(), 1);
    // The port is the protocol default, because nothing on the path set one.
    assert_eq!(effective.port.value, Some(22));
}

#[test]
fn a_config_with_no_universal_block_puts_its_connections_at_the_top_level() {
    let preview = preview_of("Host a\n  HostName a.example.com\n  Port 2222\n");
    assert_eq!(find(&preview, "a").parent_id, None);
    assert_eq!(connection(&preview, "a").port, Inherited::Explicit(2222));
    assert!(
        !preview
            .nodes()
            .iter()
            .any(|node| node.name == "ssh_config defaults")
    );
}

#[test]
fn options_written_before_the_first_host_apply_to_everything() {
    // `ssh` treats a leading run of options as if it were `Host *`.
    let preview = preview_of("ServerAliveInterval 15\nHost a\n  HostName a.example.com\n");
    let Kind::Folder(defaults) = &find(&preview, "ssh_config defaults").kind else {
        panic!("the leading options must become the defaults folder");
    };
    assert_eq!(defaults.keepalive_secs, Inherited::Explicit(15));
    assert_eq!(connection(&preview, "a").keepalive_secs, Inherited::Inherit);
}

#[test]
fn a_negated_pattern_keeps_a_block_off_the_host_it_excludes() {
    let preview = preview_of(
        "Host *.example.com !db.example.com\n  Port 2200\n\
         Host web.example.com\n  HostName web.example.com\n\
         Host db.example.com\n  HostName db.example.com\n",
    );
    assert_eq!(
        connection(&preview, "web.example.com").port,
        Inherited::Explicit(2200)
    );
    assert_eq!(
        connection(&preview, "db.example.com").port,
        Inherited::Inherit
    );
}

#[test]
fn a_host_that_names_itself_as_a_jump_target_does_not_become_its_own_gateway() {
    let preview = preview_of("Host loop\n  HostName loop.example.com\n  ProxyJump loop\n");
    assert_eq!(connection(&preview, "loop").gateway, Inherited::Inherit);
}

#[test]
fn nothing_the_config_holds_reaches_a_summary_as_a_secret() {
    let preview = preview_of(ESTATE);
    // An ssh_config holds no passwords, so the strongest claim available is
    // that nothing was marked as needing sealing.
    assert!(
        preview
            .summaries()
            .iter()
            .all(|summary| !summary.has_secret)
    );
    assert_eq!(preview.report().counts().secrets, 0);
    assert_eq!(
        Finding::GatewayMapped {
            item: "x".to_owned(),
            hops: 1
        }
        .severity(),
        Severity::Info
    );
    // And no `ImportedSecret` was constructed at all.
    assert!(preview.nodes().iter().all(|node| node.secret().is_none()));
}

#[test]
fn the_line_and_node_ceilings_refuse_a_config_built_to_exhaust_them() {
    let limits = Limits {
        max_nodes: 4,
        ..Limits::new()
    };
    let many: String = (0..64)
        .map(|i| format!("Host h{i}\n  HostName h{i}.example.com\n"))
        .collect();
    let Err(err) = parse(many.as_bytes(), &limits) else {
        panic!("the node ceiling must be enforced");
    };
    assert_eq!(err, ImportError::TooManyNodes { limit: 4 });
}
