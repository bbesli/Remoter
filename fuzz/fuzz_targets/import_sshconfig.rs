//! Fuzzes the OpenSSH config reader.
//!
//! `ssh_config::parse` is the entry point that follows no `Include`, so this
//! target never opens a file. That is deliberate: a parser that opened whatever
//! path its input named could not be fuzzed at all, and `Include /dev/urandom`
//! is a line anyone can write into a config they share.
//!
//! The interesting surface here is the pattern matcher and the first-match-wins
//! resolution across blocks. `Host a*a*a*a*a*b` against a long alias is the
//! shape that takes exponential time in the recursive matcher this one replaces,
//! so a hang is as much a finding as a crash.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{Limits, ssh_config};

fuzz_target!(|data: &[u8]| {
    let Ok(preview) = ssh_config::parse(data, &Limits::small()) else {
        return;
    };

    let (nodes, _report) = preview.into_parts();
    let mut built = Vec::with_capacity(nodes.len());
    for node in nodes {
        // An ssh_config holds no passwords, so nothing should ever need
        // sealing. Asserting it here makes a regression in the credential
        // mapping a crash rather than a surprise.
        assert!(
            !node.needs_sealing(),
            "an ssh_config produced a sealed secret"
        );
        let Ok(node) = node.into_node(0, None) else {
            panic!("a previewed node was not a valid node");
        };
        built.push(node);
    }
    let Ok(tree) = Tree::from_nodes(built) else {
        panic!("a preview was not a valid tree");
    };
    assert!(
        tree.validate_all().is_empty(),
        "a preview held a gateway chain the domain model rejects"
    );
    let _: Vec<Node> = tree.into_nodes();
});
