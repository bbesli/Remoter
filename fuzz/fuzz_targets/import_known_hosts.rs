//! Fuzzes the `known_hosts` reader.
//!
//! Every line is a small format of its own: a marker or not, a list of names
//! each of which is plain, `[host]:port`, a pattern with negations, or a
//! hashed `|1|salt|hash`, then a key whose own bytes must name the type the
//! line gives it. A fixed list of hosts is handed in, so hashed and pattern
//! names are compared with something and that path is reached.

#![no_main]

use libfuzzer_sys::fuzz_target;
use remoter_import::{Limits, known_hosts};

fuzz_target!(|data: &[u8]| {
    let hosts = [
        (String::from("web-01.example.com"), 22),
        (String::from("db.example.com"), 2222),
        (String::from("[2001:db8::1]"), 22),
    ];
    let Ok(file) = known_hosts::parse(data, &hosts, &Limits::small()) else {
        return;
    };
    for key in &file.keys {
        assert!(key.port != 0, "a key came back for port zero");
        assert!(!key.host.is_empty(), "a key came back for no host");
        assert!(
            key.blob.len() >= 4 + key.algorithm.len(),
            "a key came back shorter than the type it names"
        );
    }
});
