//! Fuzzes the `.rmtr` archive: its framing, and the body behind the password.
//!
//! The framing is read before any key exists, so anyone who can hand the user
//! a file reaches it. The body is read only after the password has opened the
//! archive — but the person who knows that password is the person who wrote
//! the file, so every byte of it is theirs to choose. Both halves are fed
//! arbitrary input here, and whatever the body decodes to is put through the
//! same graft an import commits, into a tree the domain model has to accept.

#![no_main]

use std::collections::BTreeSet;

use libfuzzer_sys::fuzz_target;
use remoter_core::Tree;
use remoter_import::native;
use remoter_vault::archive;

fuzz_target!(|data: &[u8]| {
    let _ = archive::probe_archive(data);

    let Ok(contents) = archive::decode_body(data) else {
        return;
    };
    let mut tree = Tree::new();
    let Ok(grafted) = native::graft(contents.nodes, &BTreeSet::new(), &tree, None, 0, 0) else {
        return;
    };
    for node in grafted.nodes {
        // A node the domain model refuses is reported, not a crash; what must
        // not happen is a panic anywhere on the way here.
        let _ = tree.insert(node);
    }
});
