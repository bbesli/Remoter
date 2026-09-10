//! Fuzzes the CSV reader.
//!
//! The state machine is small — quoted, unquoted, escaped quote, delimiter,
//! record end — which is exactly why it is worth fuzzing: an off-by-one in a
//! five-state reader is easy to write and hard to see. The delimiter is chosen
//! from the header row, so an input whose first line is unlike its body reaches
//! a different reader than the one it looks like it should.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{Limits, csv};

fuzz_target!(|data: &[u8]| {
    let Ok(preview) = csv::parse(data, &Limits::small()) else {
        return;
    };

    let (nodes, _report) = preview.into_parts();
    let mut built = Vec::with_capacity(nodes.len());
    for node in nodes {
        let sealed = node.needs_sealing().then(|| vec![0x5a; 32]);
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
