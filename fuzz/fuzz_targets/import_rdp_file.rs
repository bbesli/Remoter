//! Fuzzes the `.rdp` file reader.
//!
//! A line format, so the interesting inputs are the ones that are nearly
//! lines: a property with a colon too few, an address that is half a bracketed
//! IPv6 literal, a port glued on twice, a UTF-16 mark in front of bytes that
//! are not UTF-16. The name is fuzzed too, because it becomes the connection's
//! name and goes through the same cleaning a hostile one would.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{Limits, rdp_file};

fuzz_target!(|data: &[u8]| {
    let (name, body) = match data.iter().position(|byte| *byte == 0) {
        Some(split) => (String::from_utf8_lossy(&data[..split]).into_owned(), &data[split + 1..]),
        None => (String::new(), data),
    };
    let Ok(preview) = rdp_file::parse(body, &name, &Limits::small()) else {
        return;
    };

    let (nodes, _report) = preview.into_parts();
    let mut built = Vec::with_capacity(nodes.len());
    for node in nodes {
        let sealed = node.holds_password().then(|| vec![0x5a; 32]);
        let Ok(node) = node.into_node(0, sealed) else {
            panic!("a previewed node was not a valid node");
        };
        built.push(node);
    }
    let Ok(tree) = Tree::from_nodes(built) else {
        panic!("a preview was not a valid tree");
    };
    assert!(
        tree.validate_all().is_empty(),
        "a preview held a reference the domain model rejects"
    );
    let _: Vec<Node> = tree.into_nodes();
});
