//! Property tests for the importers.
//!
//! `docs/development/testing-strategy.md` asks for property tests wherever an
//! invariant has to hold across all inputs rather than a chosen few. The two
//! worth stating here are what the rest of the crate is built to guarantee.
//!
//! **Totality.** Every parser returns on every input. The generators here reach
//! shapes a hand-written test would not — a `Host` line with no arguments, a
//! quote in the middle of an unquoted field, a folder path of nothing but
//! slashes — and none of them may panic, hang or allocate without bound.
//!
//! **Every preview is a tree.** Whatever a parser accepts, the domain model
//! accepts: `Tree::from_nodes` succeeds and `validate_all` finds nothing. That
//! is the property that makes the preview meaningful, because a preview the
//! vault would refuse at commit time is a preview that lied to the user.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use proptest::prelude::*;
use remoter_core::{Node, Tree};
use remoter_import::{ImportPreview, ImportedSecret, Limits, csv, mremoteng, ssh_config};

/// Small limits, so a generated input reaches a ceiling instead of merely
/// approaching one.
fn limits() -> Limits {
    Limits::small()
}

/// Turns a preview into the tree it claims it would create.
fn tree_of(preview: ImportPreview) -> Tree {
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| {
            // Standing in for the vault's sealing call.
            let sealed = node.needs_sealing().then(|| vec![0x5a; 32]);
            node.into_node(1_700_000_000_000, sealed)
                .unwrap_or_else(|err| panic!("a previewed node was not a valid node: {err}"))
        })
        .collect();
    Tree::from_nodes(nodes).unwrap_or_else(|err| panic!("a preview was not a valid tree: {err}"))
}

/// Fragments that appear in the three formats, so a generated string is more
/// often *nearly* valid than uniformly random.
fn token() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::from("<Connections")),
        Just(String::from("<Node")),
        Just(String::from("</Node>")),
        Just(String::from("</Connections>")),
        Just(String::from(r#" Name="a""#)),
        Just(String::from(r#" Type="Container""#)),
        Just(String::from(r#" Hostname="a.example.com""#)),
        Just(String::from(r#" Protocol="SSH2""#)),
        Just(String::from(r#" Password="QQ==""#)),
        Just(String::from(r#" InheritPort="true""#)),
        Just(String::from("<!DOCTYPE x>")),
        Just(String::from("&amp;")),
        Just(String::from("&nope;")),
        Just(String::from("Host ")),
        Just(String::from("Match ")),
        Just(String::from("Include ")),
        Just(String::from("ProxyJump ")),
        Just(String::from("ProxyCommand ")),
        Just(String::from("IdentityFile ")),
        Just(String::from("name,host\n")),
        Just(String::from("\"")),
        Just(String::from(",")),
        Just(String::from(";")),
        Just(String::from("\n")),
        Just(String::from("  ")),
        Just(String::from("*")),
        Just(String::from("!")),
        Just(String::from("=")),
        Just(String::from("#")),
        Just(String::from("%h")),
        "[a-z0-9.@:/-]{0,12}",
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Arbitrary bytes never take a parser down.
    #[test]
    fn no_parser_panics_on_arbitrary_bytes(bytes in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let password = ImportedSecret::from("mR3m");
        let _ = mremoteng::parse(&bytes, Some(&password), &limits());
        let _ = mremoteng::inspect(&bytes, &limits());
        let _ = ssh_config::parse(&bytes, &limits());
        let _ = csv::parse(&bytes, &limits());
        let _ = remoter_import::detect(&bytes);
    }

    /// Nor does text assembled from the fragments these formats are made of,
    /// which is where the interesting near-misses live.
    #[test]
    fn no_parser_panics_on_near_miss_text(
        parts in proptest::collection::vec(token(), 0..64)
    ) {
        let text = parts.concat();
        let password = ImportedSecret::from("mR3m");
        let _ = mremoteng::parse(text.as_bytes(), Some(&password), &limits());
        let _ = ssh_config::parse(text.as_bytes(), &limits());
        let _ = csv::parse(text.as_bytes(), &limits());
    }

    /// Whatever the CSV importer accepts is a tree the domain model accepts.
    #[test]
    fn every_csv_preview_is_a_valid_tree(
        rows in proptest::collection::vec(
            (
                "[a-zA-Z0-9 _-]{0,20}",
                prop_oneof![
                    Just(String::from("a.example.com")),
                    Just(String::from("10.0.0.1")),
                    Just(String::from("[fe80::1]")),
                    Just(String::new()),
                    "[a-z0-9. -]{0,20}",
                ],
                prop_oneof![Just(String::new()), "[a-z/]{0,16}"],
                prop_oneof![Just(String::new()), "[0-9]{0,6}"],
                prop_oneof![Just(String::new()), "[a-zA-Z0-9]{0,12}"],
                prop_oneof![Just(String::new()), "[!-~]{0,16}"],
            ),
            0..24,
        )
    ) {
        let mut text = String::from("name,host,folder,port,username,password,gateway\n");
        for (name, host, folder, port, user, password) in &rows {
            // The gateway column deliberately points at the row's own name
            // some of the time, which is the self-reference the mapping has to
            // refuse rather than build a loop from.
            text.push_str(&format!("{name},{host},{folder},{port},{user},{password},{name}\n"));
        }
        let preview = csv::parse(text.as_bytes(), &limits());
        if let Ok(preview) = preview {
            let tree = tree_of(preview);
            prop_assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        }
    }

    /// And whatever the ssh_config importer accepts is one too.
    #[test]
    fn every_ssh_config_preview_is_a_valid_tree(
        hosts in proptest::collection::vec(
            (
                prop_oneof![
                    "[a-z0-9-]{1,12}",
                    Just(String::from("*")),
                    "[a-z*?!.-]{0,12}",
                ],
                prop_oneof![Just(String::new()), "[a-z0-9.-]{0,24}"],
                prop_oneof![Just(String::new()), "[0-9]{0,6}"],
                prop_oneof![Just(String::new()), "[a-z0-9,@:-]{0,20}"],
            ),
            0..16,
        )
    ) {
        let mut text = String::new();
        for (pattern, hostname, port, jump) in &hosts {
            text.push_str(&format!("Host {pattern}\n"));
            if !hostname.is_empty() {
                text.push_str(&format!("  HostName {hostname}\n"));
            }
            if !port.is_empty() {
                text.push_str(&format!("  Port {port}\n"));
            }
            if !jump.is_empty() {
                text.push_str(&format!("  ProxyJump {jump}\n"));
            }
        }
        if let Ok(preview) = ssh_config::parse(text.as_bytes(), &limits()) {
            let tree = tree_of(preview);
            prop_assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        }
    }

    /// And whatever the mRemoteNG importer accepts is one too, including the
    /// inheritance it carried across.
    #[test]
    fn every_mremoteng_preview_is_a_valid_tree(
        nodes in proptest::collection::vec(
            (
                "[a-zA-Z0-9 _-]{0,16}",
                prop_oneof![Just(true), Just(false)],
                prop_oneof![
                    Just(String::from("a.example.com")),
                    Just(String::from("10.0.0.1")),
                    Just(String::new()),
                    "[a-z0-9. -]{0,16}",
                ],
                prop_oneof![
                    Just(String::from("SSH2")),
                    Just(String::from("RDP")),
                    Just(String::from("ExtApp")),
                    "[A-Za-z0-9]{0,8}",
                ],
                prop_oneof![Just(String::new()), "[0-9]{0,6}"],
                prop_oneof![Just(true), Just(false)],
                prop_oneof![Just(String::new()), "[a-z]{0,8}"],
            ),
            0..12,
        )
    ) {
        let mut text = String::from(
            r#"<Connections Name="x" Protected="" ConfVersion="2.6">"#,
        );
        let mut open = 0usize;
        for (name, container, host, protocol, port, inherit, user) in &nodes {
            let kind = if *container { "Container" } else { "Connection" };
            text.push_str(&format!(
                r#"<Node Name="{name}" Type="{kind}" Hostname="{host}" Protocol="{protocol}" \
Port="{port}" Username="{user}" InheritPort="{inherit}" InheritUsername="{inherit}" \
InheritPassword="{inherit}" InheritDomain="{inherit}">"#
            ).replace("\\\n", ""));
            open += 1;
        }
        for _ in 0..open {
            text.push_str("</Node>");
        }
        text.push_str("</Connections>");

        if let Ok(preview) = mremoteng::parse(text.as_bytes(), None, &limits()) {
            let tree = tree_of(preview);
            prop_assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());
        }
    }

    /// A CSV row that names a usable host always produces exactly one
    /// connection, whatever else is on the row.
    #[test]
    fn a_usable_row_always_becomes_exactly_one_connection(
        names in proptest::collection::vec("[a-z][a-z0-9]{0,10}", 1..12)
    ) {
        let mut text = String::from("name,host\n");
        for name in &names {
            text.push_str(&format!("{name},{name}.example.com\n"));
        }
        let preview = csv::parse(text.as_bytes(), &limits()).unwrap();
        prop_assert_eq!(preview.report().counts().connections, names.len());
        prop_assert_eq!(preview.report().counts().skipped, 0);
    }

    /// No parser ever puts a value it read into a report or a summary that was
    /// meant to be sealed.
    #[test]
    fn a_recovered_password_never_reaches_the_wire(
        password in "[a-zA-Z0-9]{8,24}"
    ) {
        let text = format!("name,host,username,password\na,a.example.com,root,{password}\n");
        let preview = csv::parse(text.as_bytes(), &limits()).unwrap();
        let rendered = format!(
            "{}{}{preview:?}",
            serde_json::to_string(&preview.summaries()).unwrap(),
            serde_json::to_string(preview.report()).unwrap(),
        );
        prop_assert!(!rendered.contains(&password));
        prop_assert_eq!(preview.report().counts().secrets, 1);
    }
}
