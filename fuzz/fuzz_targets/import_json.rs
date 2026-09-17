//! Fuzzes the reader for Remoter's own JSON export.
//!
//! A JSON export is a file a person carries between machines and edits by hand
//! in version control, so it is read as hostile: whatever it decodes to is put
//! through the same graft an import commits, into a tree the domain model has
//! to accept or refuse without a panic.

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use remoter_core::Tree;
use remoter_import::{Limits, native};

fuzz_target!(|data: &[u8]| {
    let Ok((nodes, _report)) = native::parse_json(data, &Limits::small(), &[0]) else {
        return;
    };
    let mut tree = Tree::new();
    let Ok(grafted) = native::graft(nodes, &BTreeSet::new(), &tree, None, 0, 0) else {
        return;
    };
    for node in grafted.nodes {
        let _ = tree.insert(node);
    }
});
