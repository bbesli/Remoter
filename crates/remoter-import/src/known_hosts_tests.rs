//! Tests for the `known_hosts` reader.
//!
//! The hashed names below were made outside this crate — HMAC-SHA1 with the
//! salt `01 02 … 14` over `web-01.example.com`, `[db.example.com]:2222` and
//! `192.0.2.10` — so the test does not check the implementation against itself.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use super::*;

const ED25519: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcH";
const ED25519_OTHER: &str = "AAAAC3NzaC1lZDI1NTE5AAAAIAkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJ";
const RSA: &str = "AAAAB3NzaC1yc2EAAAADAQABAAAAQKurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=";

const HASHED_WEB: &str = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|8y5F4JDs7jm/Vivt/BsUoqMHxEM=";
const HASHED_DB: &str = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|iYa4+uOFt89dlRDRVGHvdqFn7NM=";
const HASHED_IP: &str = "|1|AQIDBAUGBwgJCgsMDQ4PEBESExQ=|C7hpP2A5a3TKQa/fGcha2uWW/Dg=";

fn vault_hosts() -> Vec<(String, u16)> {
    vec![
        ("Web-01.example.com".to_owned(), 22),
        ("db.example.com".to_owned(), 2222),
        ("app.internal.example.com".to_owned(), 22),
    ]
}

fn read(text: &str) -> KnownHostsFile {
    parse(text.as_bytes(), &vault_hosts(), &Limits::new()).unwrap()
}

fn key(host: &str, port: u16, algorithm: &str) -> HostKey {
    let encoded = match algorithm {
        "ssh-rsa" => RSA,
        _ => ED25519,
    };
    HostKey {
        host: host.to_owned(),
        port,
        algorithm: algorithm.to_owned(),
        blob: BASE64.decode(encoded.as_bytes()).unwrap(),
    }
}

#[test]
fn plain_names_are_taken_as_written_with_their_ports() {
    let file = read(&format!(
        "# a comment\n\
         bastion.example.com,192.0.2.1 ssh-ed25519 {ED25519} alex@laptop\n\
         [git.example.com]:2200 ssh-rsa {RSA}\n\
         2001:db8::5 ssh-ed25519 {ED25519}\n\
         [2001:db8::6]:2222 ssh-ed25519 {ED25519}\n\n"
    ));
    assert_eq!(file.entries, 4);
    assert_eq!(
        file.keys,
        vec![
            key("bastion.example.com", 22, "ssh-ed25519"),
            key("192.0.2.1", 22, "ssh-ed25519"),
            key("git.example.com", 2200, "ssh-rsa"),
            key("[2001:db8::5]", 22, "ssh-ed25519"),
            key("[2001:db8::6]", 2222, "ssh-ed25519"),
        ]
    );
    assert_eq!(file.malformed, 0);
}

#[test]
fn a_hashed_name_is_found_by_asking_for_the_vaults_hosts() {
    let file = read(&format!(
        "{HASHED_WEB} ssh-ed25519 {ED25519}\n\
         {HASHED_DB} ssh-rsa {RSA}\n\
         {HASHED_IP} ssh-ed25519 {ED25519}\n"
    ));
    assert_eq!(
        file.keys,
        vec![
            key("web-01.example.com", 22, "ssh-ed25519"),
            key("db.example.com", 2222, "ssh-rsa"),
        ]
    );
    // 192.0.2.10 is not a connection in this vault, so its line says nothing.
    assert_eq!(file.hashed_unmatched, 1);
}

#[test]
fn a_pattern_vouches_for_the_vault_hosts_it_matches_less_its_negations() {
    let file = read(&format!(
        "*.example.com,!db.example.com ssh-ed25519 {ED25519}\n\
         *.nowhere.test ssh-ed25519 {ED25519}\n\
         [db.example.*]:2222 ssh-rsa {RSA}\n"
    ));
    assert_eq!(
        file.keys,
        vec![
            key("web-01.example.com", 22, "ssh-ed25519"),
            key("app.internal.example.com", 22, "ssh-ed25519"),
            key("db.example.com", 2222, "ssh-rsa"),
        ]
    );
    assert_eq!(file.patterns_unmatched, 1);
}

#[test]
fn a_negation_takes_a_plain_name_out_of_its_own_line() {
    let file = read(&format!(
        "a.example.com,b.example.com,!b.* ssh-ed25519 {ED25519}\n"
    ));
    assert_eq!(file.keys, vec![key("a.example.com", 22, "ssh-ed25519")]);
}

#[test]
fn a_revoked_key_is_never_returned_and_an_authority_is_only_counted() {
    let file = read(&format!(
        "bastion.example.com ssh-ed25519 {ED25519}\n\
         @revoked * ssh-ed25519 {ED25519}\n\
         @cert-authority *.example.com ssh-rsa {RSA}\n\
         git.example.com ssh-rsa {RSA}\n"
    ));
    assert_eq!(file.keys, vec![key("git.example.com", 22, "ssh-rsa")]);
    assert_eq!(file.revoked, 1);
    assert_eq!(file.certificate_authorities, 1);
}

#[test]
fn the_same_host_vouched_for_twice_keeps_the_first_key_and_says_so() {
    let file = read(&format!(
        "web.example.com ssh-ed25519 {ED25519}\n\
         web.example.com ssh-ed25519 {ED25519}\n\
         web.example.com ssh-ed25519 {ED25519_OTHER}\n"
    ));
    assert_eq!(file.keys, vec![key("web.example.com", 22, "ssh-ed25519")]);
    assert_eq!(file.conflicting, 1);
}

#[test]
fn lines_it_cannot_use_are_counted_not_raised() {
    let file = read(&format!(
        "only-a-name\n\
         web.example.com ssh-ed25519\n\
         web.example.com ssh-ed25519 not*base64\n\
         web.example.com ssh-rsa {ED25519}\n\
         |1|broken ssh-ed25519 {ED25519}\n\
         @marker web.example.com ssh-ed25519 {ED25519}\n\
         [web.example.com]:0 ssh-ed25519 {ED25519}\n"
    ));
    assert!(file.keys.is_empty(), "{:?}", file.keys);
    assert_eq!(file.entries, 7);
    assert_eq!(file.malformed, 7);
}

#[test]
fn the_hashing_budget_ends_in_a_count_not_a_hang() {
    // A thousand lines allow 10 000 comparisons; this file asks for 50 000.
    let hosts: Vec<(String, u16)> = (0..50)
        .map(|n| (format!("host-{n}.example.com"), 22))
        .collect();
    let mut text = String::new();
    for _ in 0..1_000 {
        text.push_str(HASHED_WEB);
        text.push_str(" ssh-ed25519 ");
        text.push_str(ED25519);
        text.push('\n');
    }
    let limits = Limits {
        max_items: 1_000,
        ..Limits::new()
    };
    let file = parse(text.as_bytes(), &hosts, &limits).unwrap();
    assert_eq!(file.hashed_unmatched, 200);
    assert_eq!(file.hashed_unchecked, 800);
}

#[test]
fn the_bounds_hold() {
    let limits = Limits {
        max_items: 2,
        ..Limits::small()
    };
    let text =
        format!("a ssh-ed25519 {ED25519}\nb ssh-ed25519 {ED25519}\nc ssh-ed25519 {ED25519}\n");
    assert!(matches!(
        parse(text.as_bytes(), &[], &limits),
        Err(ImportError::TooManyItems { .. })
    ));
    let long = format!("{} ssh-ed25519 {ED25519}\n", "a".repeat(5000));
    assert!(matches!(
        parse(long.as_bytes(), &[], &Limits::small()),
        Err(ImportError::ValueTooLong { .. })
    ));
}
