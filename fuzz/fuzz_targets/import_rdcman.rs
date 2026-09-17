//! Fuzzes the Remote Desktop Connection Manager reader.
//!
//! The XML underneath is the hardened reader every XML importer shares, and
//! that has its own coverage through `import_mremoteng`. What this reaches is
//! the walk over the element tree: settings blocks in either schema's place,
//! `inherit` spelled any way at all, a profile that names a profile, groups
//! nested to the depth limit, and a `<file>` that is not where it should be.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{Limits, rdcman};

fuzz_target!(|data: &[u8]| {
    let Ok(preview) = rdcman::parse(data, &Limits::small()) else {
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
