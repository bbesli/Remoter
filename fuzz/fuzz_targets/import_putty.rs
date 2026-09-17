//! Fuzzes PuTTY's saved sessions: a `reg export`, and one Unix session file.
//!
//! A registry export is line-shaped text with its own quoting — `\\` and `\"`
//! inside a value, a hex value that runs on over lines ending in `\` — and a
//! key path whose last part is a `%XX`-escaped session name. The first byte
//! chooses the file name a session file is read under, because the name is
//! unescaped and becomes the connection's name.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{Limits, putty};

fuzz_target!(|data: &[u8]| {
    let (name, body) = match data.iter().position(|byte| *byte == 0) {
        Some(split) => (String::from_utf8_lossy(&data[..split]).into_owned(), &data[split + 1..]),
        None => (String::from("session"), data),
    };
    let _ = putty::unescape_name(&name);
    let Ok(preview) = putty::parse_file(body, &name, &Limits::small()) else {
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
