//! Fuzzes the mRemoteNG `confCons.xml` reader.
//!
//! Both entry points, and both password cases: the published default, which is
//! what an unprotected file opens on, and a supplied one, which is what reaches
//! the decryption paths. Whatever comes back, the invariant is the same — a
//! preview or a typed error, never a panic, an unbounded allocation or a loop
//! that does not end.
//!
//! `Limits::small` rather than the shipping defaults, because a fuzzer that has
//! to build a 32 MiB input before it can reach the size ceiling will never
//! reach it.
//!
//! A preview that comes back is put through the domain model as well: `into_node`
//! plus `Tree::from_nodes` is the same path the commit takes, so a mapping that
//! produces something the vault would reject is a crash here rather than a
//! failure in front of a user with four hundred connections to import.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_core::{Node, Tree};
use remoter_import::{ImportPreview, ImportedSecret, Limits, mremoteng};

fuzz_target!(|data: &[u8]| {
    let limits = Limits::small();

    let _ = mremoteng::inspect(data, &limits);

    if let Ok(preview) = mremoteng::parse(data, None, &limits) {
        check(preview);
    }

    // A supplied password takes the branch an unprotected file does not.
    let password = ImportedSecret::from("letmein");
    if let Ok(preview) = mremoteng::parse(data, Some(&password), &limits) {
        check(preview);
    }
});

/// Everything a preview claims it would create has to be something the domain
/// model accepts.
fn check(preview: ImportPreview) {
    let (nodes, _report) = preview.into_parts();
    let mut built = Vec::with_capacity(nodes.len());
    for node in nodes {
        // Standing in for the vault's sealing call, which this crate has no
        // access to and the fuzzer has no need of.
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
}
