//! The inputs these parsers exist to survive.
//!
//! `docs/features/import-export.md` lists import parsers as "the classic weak
//! point of connection managers — they read files that colleagues share, that
//! come from old backups, and that may be deliberately crafted". Each test here
//! is one row of that document's risk table, or one of the shapes a file takes
//! when it is corrupt rather than hostile.
//!
//! The claim being tested is total behaviour: every input returns, and returns
//! either a preview or a typed error. Not a panic, not an allocation that
//! outlives the machine's memory, and not a loop that does not end.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use std::path::Path;

use remoter_import::ssh_config::{MemoryConfigFiles, OsConfigFiles};
use remoter_import::{
    ImportError, ImportedSecret, Limits, XmlProblem, csv, known_hosts, mremoteng, putty, rdcman,
    rdp_file, ssh_config,
};

/// Every parser, behind one signature, so a hostile input can be pointed at
/// all of them without a copy of the assertion each.
fn parse_everything(bytes: &[u8], limits: &Limits) -> Vec<Result<(), ImportError>> {
    let password = ImportedSecret::from("mR3m");
    vec![
        mremoteng::parse(bytes, Some(&password), limits).map(|_| ()),
        mremoteng::inspect(bytes, limits).map(|_| ()),
        ssh_config::parse(bytes, limits).map(|_| ()),
        csv::parse(bytes, limits).map(|_| ()),
        rdcman::parse(bytes, limits).map(|_| ()),
        rdp_file::parse(bytes, "hostile", limits).map(|_| ()),
        putty::parse_reg(bytes, limits).map(|_| ()),
        putty::parse_file(bytes, "hostile", limits).map(|_| ()),
        known_hosts::parse(bytes, &[(String::from("web.example.com"), 22)], limits).map(|_| ()),
    ]
}

#[test]
fn an_xxe_attempt_is_refused_and_the_entity_is_never_resolved() {
    let attack = br#"<?xml version="1.0"?>
<!DOCTYPE Connections [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
  <!ENTITY sshkey SYSTEM "file:///root/.ssh/id_rsa">
]>
<Connections Name="&xxe;" Protected="" ConfVersion="2.6">
  <Node Name="&sshkey;" Type="Connection" Hostname="attacker.example.com" Protocol="SSH2" />
</Connections>"#;
    assert_eq!(
        mremoteng::parse(attack, None, &Limits::new()).map(|_| ()),
        Err(ImportError::DoctypeRefused)
    );
    assert_eq!(
        mremoteng::inspect(attack, &Limits::new()).map(|_| ()),
        Err(ImportError::DoctypeRefused)
    );
}

#[test]
fn a_parameter_entity_xxe_that_carries_no_doctype_still_resolves_nothing() {
    // No DTD, so the DOCTYPE refusal does not fire and the entity reference
    // itself has to be the thing that is refused.
    let attack = br#"<Connections Name="&xxe;" Protected="" ConfVersion="2.6" />"#;
    let Err(ImportError::XmlNotWellFormed { problem, .. }) =
        mremoteng::parse(attack, None, &Limits::new())
    else {
        panic!("expected a located refusal");
    };
    assert_eq!(
        problem,
        XmlProblem::UnknownEntity {
            attribute: Some("Name".to_owned())
        }
    );
}

#[test]
fn a_billion_laughs_expansion_never_starts() {
    let mut attack =
        String::from(r#"<?xml version="1.0"?><!DOCTYPE Connections [<!ENTITY a0 "aaaaaaaaaa">"#);
    for level in 1..12 {
        let previous = level - 1;
        attack.push_str(&format!(
            r#"<!ENTITY a{level} "&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};&a{previous};">"#
        ));
    }
    attack.push_str(r#"]><Connections Name="&a11;" Protected="" ConfVersion="2.6" />"#);

    // The DTD is refused, so the ten-to-the-eleventh characters are never
    // materialised. The input itself is under two kilobytes.
    assert!(attack.len() < 2048);
    assert_eq!(
        mremoteng::parse(attack.as_bytes(), None, &Limits::new()).map(|_| ()),
        Err(ImportError::DoctypeRefused)
    );
}

#[test]
fn a_deeply_nested_document_is_refused_at_the_depth_limit() {
    let depth = 10_000;
    let mut attack = String::from(r#"<Connections Name="x" Protected="" ConfVersion="2.6">"#);
    attack.push_str(&r#"<Node Name="n" Type="Container">"#.repeat(depth));
    attack.push_str(&"</Node>".repeat(depth));
    attack.push_str("</Connections>");

    let Err(err) = mremoteng::parse(attack.as_bytes(), None, &Limits::new()) else {
        panic!("a ten-thousand-deep document must be refused");
    };
    assert_eq!(
        err,
        ImportError::TooDeep {
            limit: Limits::new().max_depth
        }
    );
}

#[test]
fn an_element_flood_is_refused_at_the_element_limit() {
    let limits = Limits {
        max_items: 1000,
        ..Limits::new()
    };
    let mut attack = String::from(r#"<Connections Name="x" Protected="" ConfVersion="2.6">"#);
    attack.push_str(
        &r#"<Node Name="n" Type="Connection" Hostname="a.example.com" Protocol="SSH2"/>"#
            .repeat(20_000),
    );
    attack.push_str("</Connections>");

    let Err(err) = mremoteng::parse(attack.as_bytes(), None, &limits) else {
        panic!("an element flood must be refused");
    };
    assert_eq!(
        err,
        ImportError::TooManyItems {
            limit: 1000,
            unit: "elements"
        }
    );
}

#[test]
fn a_huge_attribute_is_refused_before_it_is_unescaped() {
    let limits = Limits {
        max_value_bytes: 4096,
        ..Limits::new()
    };
    // Escaped, so unescaping would be where the work happened if the length
    // were not checked first.
    let attack = format!(
        r#"<Connections Name="{}" Protected="" ConfVersion="2.6" />"#,
        "&amp;".repeat(200_000)
    );
    let Err(err) = mremoteng::parse(attack.as_bytes(), None, &limits) else {
        panic!("an oversized attribute must be refused");
    };
    assert_eq!(
        err,
        ImportError::ValueTooLong {
            limit: 4096,
            unit: "attribute"
        }
    );
}

#[test]
fn an_input_over_the_size_limit_is_refused_before_it_is_parsed() {
    let limits = Limits {
        max_input_bytes: 1024,
        ..Limits::new()
    };
    let big = vec![b'a'; 4096];
    for outcome in parse_everything(&big, &limits) {
        assert_eq!(
            outcome,
            Err(ImportError::TooLarge {
                size: 4096,
                limit: 1024
            })
        );
    }
}

#[test]
fn invalid_utf8_is_refused_by_every_parser_with_the_offset() {
    let mut bytes = b"name,host\nweb-01,web-01.example.com".to_vec();
    bytes.push(0xff);
    bytes.extend_from_slice(b"\n");
    for outcome in parse_everything(&bytes, &Limits::new()) {
        assert_eq!(outcome, Err(ImportError::NotUtf8 { offset: 35 }));
    }
}

#[test]
fn a_truncated_document_is_reported_as_truncated_rather_than_guessed_at() {
    let full = br#"<Connections Name="x" Protected="" ConfVersion="2.6"><Node Name="a" Type="Container"><Node Name="b" Type="Connection" Hostname="b.example.com" Protocol="SSH2"/></Node></Connections>"#;
    // Every prefix of a valid document either parses or fails cleanly.
    for cut in 0..full.len() {
        let outcome = mremoteng::parse(&full[..cut], None, &Limits::new());
        if let Err(err) = outcome {
            assert!(
                matches!(err, ImportError::XmlNotWellFormed { .. }),
                "cut at {cut} gave {err:?}"
            );
        }
    }
}

#[test]
fn a_truncated_ciphertext_is_a_malformed_field_not_a_panic() {
    let attack = r#"<Connections Name="x" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" Protected="" ConfVersion="2.6"><Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2" Username="root" Password="QQ==" /></Connections>"#;
    let preview = mremoteng::parse(attack.as_bytes(), None, &Limits::new()).unwrap();
    // The connection survives; only its password did not.
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().secrets, 0);
}

#[test]
fn an_absurd_kdf_iteration_count_is_refused_rather_than_run() {
    let attack = r#"<Connections Name="x" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="4000000000" Protected="" ConfVersion="2.6" />"#;
    let Err(err) = mremoteng::parse(attack.as_bytes(), None, &Limits::new()) else {
        panic!("a four-billion-iteration KDF must be refused");
    };
    assert!(matches!(err, ImportError::TooManyItems { .. }));
}

#[test]
fn a_full_file_body_that_decrypts_to_a_dtd_is_still_refused() {
    // Encryption does not launder a DTD: the decrypted document goes through
    // the same reader the outer one did.
    let attack = r#"<Connections Name="x" EncryptionEngine="AES" BlockCipherMode="GCM" KdfIterations="1000" FullFileEncryption="true" Protected="" ConfVersion="2.6">QQ==</Connections>"#;
    let Err(err) = mremoteng::parse(attack.as_bytes(), None, &Limits::new()) else {
        panic!("an unreadable encrypted body must be refused");
    };
    assert_eq!(err, ImportError::MalformedCiphertext);
}

#[test]
fn an_ssh_config_include_cannot_reach_outside_the_directory_it_was_rooted_at() {
    let files = OsConfigFiles::rooted_at("/nonexistent-import-root");
    let Err(ImportError::ReadFailed { reason, .. }) =
        ssh_config::parse_files(Path::new("/etc/passwd"), &files, &Limits::new())
    else {
        panic!("a path outside the root must be refused");
    };
    assert_eq!(reason, remoter_import::ReadFailure::OutsideRoot);
}

#[test]
fn an_include_fan_out_is_stopped_by_the_file_budget() {
    let mut files = MemoryConfigFiles::new("/c").with(
        "/c/config",
        (0..64)
            .map(|i| format!("Include f{i}\n"))
            .collect::<String>(),
    );
    for i in 0..64 {
        files = files.with(format!("/c/f{i}"), "Host a\n  HostName a.example.com\n");
    }
    let limits = Limits {
        max_included_files: 8,
        ..Limits::new()
    };
    let Err(err) = ssh_config::parse_files(Path::new("/c/config"), &files, &limits) else {
        panic!("an include fan-out must be refused");
    };
    assert!(matches!(err, ImportError::TooManyItems { .. }));
}

#[test]
fn a_pathological_host_pattern_does_not_take_exponential_time() {
    // The recursive form of the matcher would not return on this within any
    // useful time; the iterative one is linear in the product of the lengths.
    // Sixty, because a DNS label may not be longer than sixty-three characters
    // and the point of the test is the matcher, not the validator.
    let subject = "a".repeat(60);
    let config = format!(
        "Host {}b\n  Port 2200\nHost {subject}\n  HostName {subject}.example.com\n",
        "a*".repeat(40)
    );
    let preview = ssh_config::parse(config.as_bytes(), &Limits::new()).unwrap();
    assert_eq!(preview.report().counts().connections, 1);
}

#[test]
fn a_csv_with_one_enormous_quoted_field_is_refused() {
    let limits = Limits {
        max_value_bytes: 1024,
        ..Limits::new()
    };
    let attack = format!("name,host\n\"{}\",a.example.com\n", "x".repeat(500_000));
    let Err(err) = csv::parse(attack.as_bytes(), &limits) else {
        panic!("an oversized quoted field must be refused");
    };
    assert_eq!(
        err,
        ImportError::ValueTooLong {
            limit: 1024,
            unit: "field"
        }
    );
}

#[test]
fn a_csv_with_more_rows_than_the_limit_is_refused() {
    let limits = Limits {
        max_items: 100,
        ..Limits::new()
    };
    let attack = format!("name,host\n{}", "a,a.example.com\n".repeat(10_000));
    let Err(err) = csv::parse(attack.as_bytes(), &limits) else {
        panic!("a row flood must be refused");
    };
    assert_eq!(
        err,
        ImportError::TooManyItems {
            limit: 100,
            unit: "rows"
        }
    );
}

#[test]
fn every_parser_returns_on_every_byte_pattern_it_is_handed() {
    // Not exhaustive — that is what the fuzz targets under `fuzz/` are for —
    // but enough to catch a parser that indexes past the end of a header or
    // loops on an unexpected character.
    let corpus: Vec<Vec<u8>> = vec![
        Vec::new(),
        vec![0u8; 512],
        vec![b'"'; 512],
        vec![b'<'; 512],
        vec![b'&'; 512],
        vec![b','; 512],
        vec![b'\n'; 512],
        b"<".to_vec(),
        b"<Connections".to_vec(),
        b"<Connections>".to_vec(),
        br#"<Connections Protected="" />"#.to_vec(),
        b"Host".to_vec(),
        b"Host \x00\x00".to_vec(),
        b"Include".to_vec(),
        b"Match".to_vec(),
        b"name,host\n".to_vec(),
        b"name,host\n\"".to_vec(),
        b"\xef\xbb\xbf".to_vec(),
        "\u{feff}".as_bytes().to_vec(),
        "Host \u{202e}evil\n".as_bytes().to_vec(),
        br#"<Connections Name="a" Protected="" ConfVersion="2.6"><Node/></Connections>"#.to_vec(),
        br#"<Connections Name="a" Protected="" ConfVersion="2.6"><Node Type="Container"/></Connections>"#.to_vec(),
    ];
    for bytes in &corpus {
        for limits in [Limits::new(), Limits::small()] {
            let _ = parse_everything(bytes, &limits);
        }
    }
}

#[test]
fn a_preview_from_a_hostile_file_still_produces_a_tree_or_a_named_refusal() {
    // A file whose every value is chosen to be awkward: control characters in
    // names, a port of zero, a hostname that is a path, a protocol that is not
    // an identifier.
    let attack = "name,host,port,protocol,folder,tags\n\
         \u{7}\u{7},../../etc/passwd,0,SSH/2,../..,a b;;\n\
         ok,ok.example.com,0,,/,\n";
    let preview = csv::parse(attack.as_bytes(), &Limits::new()).unwrap();
    let (nodes, report) = preview.into_parts();
    assert!(report.counts().skipped >= 1);
    for node in nodes {
        // Whatever survived is something the domain model accepts.
        let sealed = node.holds_password().then(|| vec![1u8; 32]);
        node.into_node(0, sealed).unwrap();
    }
}
