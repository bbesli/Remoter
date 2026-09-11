//! The structural half of "this crate never opens its own socket".
//!
//! ADR-0003 makes transport injection the organising principle: a protocol
//! adapter is handed an already-connected `Box<dyn Transport>`, which is what
//! makes a jump-host chain, a SOCKS proxy and an SSH tunnel the same code path
//! for every protocol. An adapter that dialled for itself would still work on a
//! LAN and would silently lose gateway support — and it would lose it quietly,
//! because a direct connection and a tunnelled one look identical until the
//! tunnel is the only way through.
//!
//! The behavioural half of the proof is in the crate's own tests: every session
//! there runs over a `tokio::io::duplex` pair, and none of them could pass if a
//! connection were being opened somewhere else.
//!
//! This is the half that catches the *next* change. A `TcpStream::connect`
//! added to a retry path a year from now would not break the pipe tests — the
//! session would simply take a different route — so the source is checked for
//! the APIs that could do it. Reading source in a test is unusual and it is
//! deliberate: the property being protected is "this code does not exist",
//! and no runtime assertion can express that.
//!
//! Note what is *not* relied on here. `Cargo.toml` asks for `tokio` without the
//! `net` feature, which would make `tokio::net` absent — but cargo unifies
//! features across a workspace build, so a sibling crate enabling `net` makes
//! it present again. The declaration states the intent; this test enforces it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::fs;
use std::path::{Path, PathBuf};

/// Fragments that can only appear in code that opens or accepts a connection.
///
/// Each is the *name* of something that dials, so a match is a finding rather
/// than a hint. `lookup_host` is included because resolution is a network
/// operation too: `docs/architecture/session-pipeline.md` puts it inside the
/// connect deadline for exactly that reason, and a resolver answer is
/// attacker-influenced input this crate has no business consuming.
const DIALLING: &[&str] = &[
    "TcpStream::connect",
    "TcpListener::bind",
    "UdpSocket::bind",
    "lookup_host",
    "ToSocketAddrs",
    "TcpTransport::connect",
    "tokio::net::",
    "std::net::TcpStream",
];

/// Files exempt from the scan, with the reason.
///
/// Nothing is exempt today. The list exists so that an exemption has to be
/// written down beside a reason rather than added by loosening the pattern.
const EXEMPT: &[(&str, &str)] = &[];

fn crate_source() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_files(directory: &Path, found: &mut Vec<PathBuf>) {
    let entries = fs::read_dir(directory).expect("the crate's source directory is readable");
    for entry in entries {
        let path = entry.expect("a directory entry is readable").path();
        if path.is_dir() {
            rust_files(&path, found);
        } else if path.extension().is_some_and(|extension| extension == "rs") {
            found.push(path);
        }
    }
}

#[test]
fn nothing_in_this_crate_can_open_a_connection() {
    let root = crate_source();
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(
        files.len() >= 8,
        "the scan found only {} files; it is looking in the wrong place",
        files.len()
    );

    let mut findings = Vec::new();
    for file in &files {
        let name = file
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if EXEMPT.iter().any(|(exempt, _)| *exempt == name) {
            continue;
        }
        let source = fs::read_to_string(file).expect("source files are UTF-8 text");
        for (number, line) in source.lines().enumerate() {
            // Comments are skipped, and only comments. A line of prose that
            // says "nothing here calls `lookup_host`" is the documentation this
            // rule wants written, and a scan that punished it would be a scan
            // people work around by not writing the comment. Nothing inside a
            // `//` can dial anything.
            if line.trim_start().starts_with("//") {
                continue;
            }
            for needle in DIALLING {
                if line.contains(needle) {
                    findings.push(format!("{name}:{}: {}", number + 1, line.trim()));
                }
            }
        }
    }

    assert!(
        findings.is_empty(),
        "this crate must receive its transport, never open one (ADR-0003):\n{}",
        findings.join("\n")
    );
}

#[test]
fn the_scan_would_notice_if_a_connection_were_opened() {
    // A guard that always passes protects nothing. This checks the matcher
    // against the line it exists to catch.
    let offending = "        let stream = TcpStream::connect(target).await?;";
    assert!(
        DIALLING.iter().any(|needle| offending.contains(needle)),
        "the pattern list has stopped matching the thing it forbids"
    );

    let innocent = "    /// The transport is injected, never dialled (ADR-0003).";
    assert!(
        !DIALLING.iter().any(|needle| innocent.contains(needle)),
        "the pattern list must not fire on prose"
    );

    // A comment that names the forbidden call is documentation, not a dial, and
    // the scan skips it by looking at the line's first non-space characters.
    let documented = "//! There is no `lookup_host` anywhere below.";
    assert!(documented.trim_start().starts_with("//"));
    assert!(!offending.trim_start().starts_with("//"));
}
