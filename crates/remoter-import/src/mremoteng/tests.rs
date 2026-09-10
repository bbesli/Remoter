//! Tests for the mRemoteNG importer.
//!
//! The encrypted fixtures are built here rather than checked in, by the
//! encrypting half of the same two schemes the importer reads. A decryption
//! path fed only hand-typed constants is a decryption path nobody has
//! exercised, and a checked-in `confCons.xml` with real ciphertext in it is the
//! sort of file `.gitignore` exists to keep out of this repository.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use remoter_core::{Node, Tree};

use super::crypto::test_encrypt::encrypt;
use super::*;
use crate::preview::PreviewKind as Kind;
use crate::report::Severity;

const GCM: CipherMode = CipherMode::Gcm { iterations: 1000 };

/// Wraps a body in a `<Connections>` root with the attributes a given scheme
/// would produce.
fn document(cipher: CipherMode, password: &str, full_file: bool, body: &str) -> String {
    let protected = encrypt(
        cipher,
        password,
        if password == DEFAULT_PASSWORD {
            "ThisIsNotProtected"
        } else {
            "ThisIsProtected"
        },
        0x5a,
    );
    let (mode, iterations) = match cipher {
        CipherMode::Gcm { iterations } => ("GCM", iterations),
        CipherMode::Cbc => ("CBC", 1000),
    };
    let body = if full_file {
        encrypt(cipher, password, body, 0x11)
    } else {
        body.to_owned()
    };
    format!(
        r#"<?xml version="1.0" encoding="utf-8"?>
<Connections xmlns:mrng="http://mremoteng.org" Name="Acme Production" Export="false" \
EncryptionEngine="AES" BlockCipherMode="{mode}" KdfIterations="{iterations}" \
FullFileEncryption="{full_file}" Protected="{protected}" ConfVersion="2.6">{body}</Connections>"#
    )
    .replace("\\\n", "")
}

/// A password field as mRemoteNG would write it.
fn secret(cipher: CipherMode, password: &str, plaintext: &str, seed: u8) -> String {
    encrypt(cipher, password, plaintext, seed)
}

/// The estate from `docs/architecture/data-model.md`, in mRemoteNG's shape:
/// a folder that sets the credential and the port, and connections beneath it
/// that inherit both.
fn datacentre(cipher: CipherMode, password: &str) -> String {
    let svc = secret(cipher, password, "hunter2", 1);
    let admin = secret(cipher, password, "s3cret", 2);
    document(
        cipher,
        password,
        false,
        &format!(
            r#"
  <Node Name="Datacentre EU-West" Type="Container" Expanded="true" Descr="Frankfurt" \
Username="svc-deploy" Domain="" Password="{svc}" Hostname="" Protocol="SSH2" Port="2222" \
Panel="General" Icon="Server">
    <Node Name="web-01" Type="Connection" Descr="" Hostname="web-01.eu.acme.internal" \
Protocol="SSH2" Port="22" Username="" Domain="" Password="" InheritPort="true" \
InheritUsername="true" InheritPassword="true" InheritDomain="true" \
RedirectClipboard="true" InheritRedirectClipboard="false" />
    <Node Name="web-02" Type="Connection" Descr="" Hostname="web-02.eu.acme.internal" \
Protocol="SSH2" Port="2022" Username="root" Domain="" Password="{admin}" />
  </Node>
  <Node Name="ctso-dc01" Type="Connection" Descr="Customer DC" \
Hostname="10.4.0.11" Protocol="RDP" Port="3389" Username="admin" Domain="CONTOSO" \
Password="{admin}" RedirectDiskDrives="true" Colors="Colors16Bit" />
"#
        ),
    )
    .replace("\\\n", "")
}

fn preview(xml: &str, password: Option<&str>) -> ImportPreview {
    let password = password.map(ImportedSecret::from);
    parse(xml.as_bytes(), password.as_ref(), &Limits::new()).unwrap()
}

/// `ImportPreview` is deliberately not comparable — it holds secrets — so a
/// refusal is asserted on the error rather than on the whole `Result`.
fn refusal(xml: &[u8], password: Option<&str>) -> ImportError {
    let password = password.map(ImportedSecret::from);
    let Err(err) = parse(xml, password.as_ref(), &Limits::new()) else {
        panic!("expected a refusal");
    };
    err
}

fn find<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewNode {
    preview
        .nodes()
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name}"))
}

fn connection<'a>(preview: &'a ImportPreview, name: &str) -> &'a ConnectionProps {
    let Kind::Connection(props) = &find(preview, name).kind else {
        panic!("{name} is not a connection");
    };
    props
}

#[test]
fn the_folder_tree_is_preserved_rather_than_flattened() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));

    let folder = find(&preview, "Datacentre EU-West");
    assert!(matches!(folder.kind, Kind::Folder(_)));
    assert_eq!(folder.parent_id, None);
    assert_eq!(folder.description, "Frankfurt");

    let web01 = find(&preview, "web-01");
    assert_eq!(web01.parent_id, Some(folder.id));
    assert_eq!(find(&preview, "web-02").parent_id, Some(folder.id));
    // A connection at the top level stays at the top level.
    assert_eq!(find(&preview, "ctso-dc01").parent_id, None);
    // Source order decides sibling order.
    assert!(web01.sort_order < find(&preview, "web-02").sort_order);
}

#[test]
fn inherit_attributes_become_inherit_and_everything_else_becomes_explicit() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));

    let Kind::Folder(folder) = &find(&preview, "Datacentre EU-West").kind else {
        panic!("the datacentre must be a folder");
    };
    assert_eq!(folder.port, Inherited::Explicit(2222));
    assert!(folder.credential.is_explicit());

    // web-01 inherits all four, so it stores none of them.
    let web01 = connection(&preview, "web-01");
    assert_eq!(web01.port, Inherited::Inherit);
    assert_eq!(web01.credential, Inherited::Inherit);

    // web-02 sets its own, so it stores them.
    let web02 = connection(&preview, "web-02");
    assert_eq!(web02.port, Inherited::Explicit(2022));
    assert!(web02.credential.is_explicit());
}

#[test]
fn protocols_and_hosts_map_onto_the_domain_model() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    assert_eq!(connection(&preview, "web-01").protocol.as_str(), "ssh");
    assert_eq!(
        connection(&preview, "web-01").host,
        "web-01.eu.acme.internal"
    );
    assert_eq!(connection(&preview, "ctso-dc01").protocol.as_str(), "rdp");
    assert_eq!(connection(&preview, "ctso-dc01").host, "10.4.0.11");
}

#[test]
fn a_gcm_encrypted_file_gives_its_passwords_back() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));

    let credentials: Vec<&PreviewNode> = preview
        .nodes()
        .iter()
        .filter(|node| matches!(node.kind, Kind::Credential(_)))
        .collect();
    let recovered: Vec<&str> = credentials
        .iter()
        .filter_map(|node| node.secret().map(ImportedSecret::expose))
        .collect();
    assert!(recovered.contains(&"hunter2"));
    assert!(recovered.contains(&"s3cret"));
    assert_eq!(preview.report().counts().secrets, 3);
}

#[test]
fn a_legacy_cbc_file_gives_its_passwords_back_and_says_what_it_was() {
    let xml = datacentre(CipherMode::Cbc, "letmein");
    let preview = preview(&xml, Some("letmein"));
    let recovered: Vec<&str> = preview
        .nodes()
        .iter()
        .filter_map(|node| node.secret().map(ImportedSecret::expose))
        .collect();
    assert!(recovered.contains(&"hunter2"));
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::LegacyCbcEncryption)
    );
    assert_eq!(Finding::LegacyCbcEncryption.severity(), Severity::Alert);
}

#[test]
fn a_file_on_the_default_password_is_reported_as_unprotected() {
    let xml = datacentre(GCM, DEFAULT_PASSWORD);
    // No password supplied: the file opens on the published constant.
    let preview = preview(&xml, None);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::DefaultFilePassword)
    );
    assert_eq!(Finding::DefaultFilePassword.severity(), Severity::Alert);
    assert!(preview.report().needs_attention());

    // A file the user really did protect says nothing of the sort.
    let protected = preview_of_protected();
    assert!(
        !protected
            .report()
            .findings()
            .contains(&Finding::DefaultFilePassword)
    );
}

fn preview_of_protected() -> ImportPreview {
    preview(&datacentre(GCM, "letmein"), Some("letmein"))
}

#[test]
fn full_file_encryption_is_decrypted_and_reported() {
    let body = r#"<Node Name="web-01" Type="Connection" Hostname="web-01.example.com" \
Protocol="SSH2" Port="22" />"#
        .replace("\\\n", "");
    let xml = document(GCM, "letmein", true, &body);
    let preview = preview(&xml, Some("letmein"));

    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(connection(&preview, "web-01").host, "web-01.example.com");
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::FullFileEncryption)
    );
}

#[test]
fn a_missing_password_and_a_wrong_one_are_different_answers() {
    let xml = datacentre(GCM, "letmein");
    assert_eq!(refusal(xml.as_bytes(), None), ImportError::PasswordRequired);
    assert_eq!(
        refusal(xml.as_bytes(), Some("nope")),
        ImportError::WrongPassword
    );
}

#[test]
fn inspect_reads_the_root_without_reading_the_body() {
    let info = inspect(datacentre(GCM, "letmein").as_bytes(), &Limits::new()).unwrap();
    assert_eq!(info.name, "Acme Production");
    assert_eq!(info.conf_version.as_deref(), Some("2.6"));
    assert_eq!(info.cipher, GCM);
    assert!(!info.full_file_encryption);
    assert!(info.password_required);

    let info = inspect(datacentre(GCM, DEFAULT_PASSWORD).as_bytes(), &Limits::new()).unwrap();
    assert!(!info.password_required);

    let info = inspect(document(GCM, "p", true, "").as_bytes(), &Limits::new()).unwrap();
    assert!(info.full_file_encryption);
}

#[test]
fn one_account_shared_between_connections_becomes_one_credential() {
    let admin = secret(GCM, "p", "same", 3);
    let xml = document(
        GCM,
        "p",
        false,
        &format!(
            r#"<Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2" \
Username="root" Password="{admin}" />
<Node Name="b" Type="Connection" Hostname="b.example.com" Protocol="SSH2" \
Username="root" Password="{admin}" />"#
        )
        .replace("\\\n", ""),
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.report().counts().credentials, 1);
    let Inherited::Explicit(a) = &connection(&preview, "a").credential else {
        panic!("a must reference a credential");
    };
    let Inherited::Explicit(b) = &connection(&preview, "b").credential else {
        panic!("b must reference a credential");
    };
    assert_eq!(a.id(), b.id());
}

#[test]
fn an_ssh_tunnel_reference_becomes_a_gateway_chain() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="web-01" Type="Connection" Hostname="web-01.example.com" \
Protocol="SSH2" SSHTunnelConnectionName="bastion" />
<Node Name="bastion" Type="Connection" Hostname="bastion.example.com" Protocol="SSH2" />"#
            .replace("\\\n", "")
            .as_str(),
    );
    let preview = preview(&xml, Some("p"));
    let bastion = find(&preview, "bastion").id;
    let Inherited::Explicit(chain) = &connection(&preview, "web-01").gateway else {
        panic!("web-01 must have a gateway chain");
    };
    assert_eq!(chain.hops.len(), 1);
    assert_eq!(chain.hops[0].node.id(), bastion);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::GatewayMapped {
                item: "web-01".to_owned(),
                hops: 1
            })
    );
}

#[test]
fn a_tunnel_naming_nothing_is_preserved_and_flagged() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="web-01" Type="Connection" Hostname="web-01.example.com" \
Protocol="SSH2" SSHTunnelConnectionName="a bastion that is not in this file" />"#
            .replace("\\\n", "")
            .as_str(),
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(connection(&preview, "web-01").gateway, Inherited::Inherit);
    assert_eq!(
        find(&preview, "web-01")
            .custom_fields
            .get("mremoteng.SSHTunnelConnectionName")
            .map(String::as_str),
        Some("a bastion that is not in this file")
    );
    assert!(
        preview
            .report()
            .findings()
            .iter()
            .any(|finding| matches!(finding, Finding::GatewayUnresolved { .. }))
    );
}

#[test]
fn settings_the_model_has_no_home_for_are_preserved_but_inherited_ones_are_not() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    let ctso = find(&preview, "ctso-dc01");
    assert_eq!(
        ctso.custom_fields
            .get("mremoteng.Colors")
            .map(String::as_str),
        Some("Colors16Bit")
    );
    assert_eq!(
        ctso.custom_fields
            .get("mremoteng.RedirectDiskDrives")
            .map(String::as_str),
        Some("true")
    );
    // web-01 sets RedirectClipboard with InheritRedirectClipboard="false", so
    // it is kept.
    assert!(
        find(&preview, "web-01")
            .custom_fields
            .contains_key("mremoteng.RedirectClipboard")
    );
    // The inheritance flags themselves are state, not data.
    assert!(
        !find(&preview, "web-01")
            .custom_fields
            .keys()
            .any(|key| key.contains("Inherit"))
    );
}

#[test]
fn an_inherited_setting_is_not_copied_onto_the_node_that_inherits_it() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="folder" Type="Container" Colors="Colors32Bit">
  <Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="RDP" \
Colors="Colors32Bit" InheritColors="true" />
</Node>"#
            .replace("\\\n", "")
            .as_str(),
    );
    let preview = preview(&xml, Some("p"));
    assert!(
        find(&preview, "folder")
            .custom_fields
            .contains_key("mremoteng.Colors")
    );
    // This is the flattening the importer exists to avoid: the value is on the
    // folder and nowhere else.
    assert!(
        !find(&preview, "a")
            .custom_fields
            .contains_key("mremoteng.Colors")
    );
}

#[test]
fn a_secret_with_no_home_in_the_model_is_dropped_and_named() {
    let gateway_password = secret(GCM, "p", "gateway-secret", 4);
    let xml = document(
        GCM,
        "p",
        false,
        &format!(
            r#"<Node Name="ctso" Type="Connection" Hostname="dc01.example.com" Protocol="RDP" \
RDGatewayHostname="gw.example.com" RDGatewayPassword="{gateway_password}" />"#
        )
        .replace("\\\n", ""),
    );
    let preview = preview(&xml, Some("p"));
    let node = find(&preview, "ctso");
    // The hostname is not a secret and is kept.
    assert!(
        node.custom_fields
            .contains_key("mremoteng.RDGatewayHostname")
    );
    // The password is not, anywhere.
    assert!(
        !node
            .custom_fields
            .values()
            .any(|value| value.contains(&gateway_password))
    );
    assert!(
        !node
            .custom_fields
            .contains_key("mremoteng.RDGatewayPassword")
    );
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretNotMapped {
                item: "ctso".to_owned(),
                field: "RDGatewayPassword".to_owned()
            })
    );
}

#[test]
fn an_unusable_host_is_skipped_and_named() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="broken" Type="Connection" Hostname="not a hostname" Protocol="SSH2" />
<Node Name="fine" Type="Connection" Hostname="fine.example.com" Protocol="SSH2" />"#,
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().skipped, 1);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "broken".to_owned(),
        reason: SkipReason::UnusableHost
    }));
}

#[test]
fn an_external_application_entry_is_skipped_rather_than_given_an_adapter() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="notepad" Type="Connection" Hostname="localhost" Protocol="ExtApp" />"#,
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.report().counts().connections, 0);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "notepad".to_owned(),
        reason: SkipReason::UnsupportedKind
    }));
}

#[test]
fn a_protocol_this_build_does_not_know_is_kept_and_flagged() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="ps" Type="Connection" Hostname="dc01.example.com" Protocol="PowerShell" />"#,
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(connection(&preview, "ps").protocol.as_str(), "powershell");
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::UnknownProtocol {
                item: "ps".to_owned(),
                protocol: "PowerShell".to_owned(),
                mapped_to: "powershell".to_owned()
            })
    );
}

#[test]
fn a_document_that_is_not_a_confcons_is_refused() {
    assert_eq!(
        refusal(b"<RoyalDocument/>", None),
        ImportError::WrongFormat {
            expected: "an mRemoteNG confCons.xml"
        }
    );
    assert_eq!(
        refusal(b"", None),
        ImportError::WrongFormat {
            expected: "an mRemoteNG confCons.xml"
        }
    );
}

#[test]
fn an_unreadable_cipher_is_refused_before_anything_is_decrypted() {
    let xml = r#"<Connections Name="x" EncryptionEngine="Twofish" BlockCipherMode="GCM" \
KdfIterations="1000" Protected="" ConfVersion="2.6" />"#
        .replace("\\\n", "");
    assert_eq!(
        refusal(xml.as_bytes(), None),
        ImportError::UnsupportedCipher {
            mode: "Twofish".to_owned()
        }
    );
}

#[test]
fn the_preview_becomes_a_tree_the_domain_model_accepts() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| {
            // Standing in for the vault, which is the IPC layer's to call.
            let sealed = node.needs_sealing().then(|| vec![0xaa; 48]);
            node.into_node(1_700_000_000_000, sealed).unwrap()
        })
        .collect();

    let tree = Tree::from_nodes(nodes).unwrap();
    assert!(tree.validate_all().is_empty(), "{:?}", tree.validate_all());

    // The point of preserving the structure: web-01 resolves the folder's port
    // and credential, and says where they came from.
    let web01 = tree
        .nodes()
        .find(|node| node.name == "web-01")
        .map(|node| node.id)
        .unwrap();
    let folder = tree
        .nodes()
        .find(|node| node.name == "Datacentre EU-West")
        .map(|node| node.id)
        .unwrap();
    let effective = tree.effective_connection(web01).unwrap();
    assert_eq!(effective.port.value, Some(2222));
    assert!(effective.port.is_inherited());
    assert_eq!(effective.port.source(), Some(folder));
    assert!(effective.credential.value.is_some());
    assert!(effective.credential.is_inherited());
}

#[test]
fn a_credential_node_carries_the_purpose_restriction_of_the_connection_it_came_from() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    let Kind::Credential(rdp) = &find(&preview, "CONTOSO\\admin").kind else {
        panic!("the RDP account must be a credential");
    };
    assert_eq!(rdp.username, "admin");
    assert_eq!(rdp.domain.as_deref(), Some("CONTOSO"));
    assert_eq!(
        rdp.allowed_protocols
            .iter()
            .map(ProtocolId::as_str)
            .collect::<Vec<_>>(),
        ["rdp"]
    );
}

#[test]
fn nothing_in_a_summary_or_a_report_carries_a_password() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    let rendered = format!(
        "{}{}",
        serde_json::to_string(&preview.summaries()).unwrap(),
        serde_json::to_string(preview.report()).unwrap()
    );
    for password in ["hunter2", "s3cret"] {
        assert!(!rendered.contains(password), "{password} reached the wire");
    }
    // The Debug of a whole preview must not either.
    let debugged = format!("{preview:?}");
    assert!(!debugged.contains("hunter2"));
    assert!(debugged.contains("ImportedSecret(<redacted>)"));
}

#[test]
fn a_node_nested_under_a_connection_attaches_to_the_nearest_container() {
    // Not something mRemoteNG writes, but something a hand-edited file can
    // contain, and a connection holds no children.
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="folder" Type="Container">
  <Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2">
    <Node Name="b" Type="Connection" Hostname="b.example.com" Protocol="SSH2" />
  </Node>
</Node>"#,
    );
    let preview = preview(&xml, Some("p"));
    let folder = find(&preview, "folder").id;
    assert_eq!(find(&preview, "a").parent_id, Some(folder));
    assert_eq!(find(&preview, "b").parent_id, Some(folder));

    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| node.into_node(0, None).unwrap())
        .collect();
    assert!(Tree::from_nodes(nodes).is_ok());
}

#[test]
fn an_element_that_is_not_a_node_is_walked_past() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Metadata Version="1"><Author Name="someone" /></Metadata>
<Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2" />"#,
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.report().counts().connections, 1);
    assert!(matches!(find(&preview, "a").kind, Kind::Connection(_)));
}

#[test]
fn a_folder_credential_is_shared_by_the_subtree_that_inherits_it() {
    let preview = preview(&datacentre(GCM, "letmein"), Some("letmein"));
    let Kind::Folder(folder) = &find(&preview, "Datacentre EU-West").kind else {
        panic!("the datacentre must be a folder");
    };
    let Inherited::Explicit(reference) = &folder.credential else {
        panic!("the folder must set a credential");
    };
    let Kind::Credential(credential) = &preview
        .nodes()
        .iter()
        .find(|node| node.id == reference.id())
        .unwrap()
        .kind
    else {
        panic!("the reference must point at a credential");
    };
    assert_eq!(credential.username, "svc-deploy");
    // A folder credential is unrestricted: it serves whatever protocols the
    // subtree beneath it speaks.
    assert!(credential.allowed_protocols.is_empty());
    assert_eq!(
        credential.secret,
        PreviewSecret::Password(ImportedSecret::from("hunter2"))
    );
}

#[test]
fn a_password_field_that_will_not_decrypt_does_not_fail_the_import() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2" \
Username="root" Password="bm90IGEgY2lwaGVydGV4dA==" />"#
            .replace("\\\n", "")
            .as_str(),
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().secrets, 0);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretNotMapped {
                item: "a".to_owned(),
                field: "Password".to_owned()
            })
    );
}

#[test]
fn a_node_with_no_usable_name_is_skipped_rather_than_named_by_the_importer() {
    let xml = document(
        GCM,
        "p",
        false,
        r#"<Node Name="" Type="Connection" Hostname="" Protocol="SSH2" />"#,
    );
    let preview = preview(&xml, Some("p"));
    assert_eq!(preview.nodes().len(), 0);
    assert_eq!(preview.report().counts().skipped, 1);
}

#[test]
fn a_node_with_more_settings_than_the_ceiling_says_the_preview_is_partial() {
    let attributes: String = (0..64).map(|i| format!(r#" Opt{i}="v""#)).collect();
    let xml = document(
        GCM,
        "p",
        false,
        &format!(
            r#"<Node Name="a" Type="Connection" Hostname="a.example.com" Protocol="SSH2"{attributes} />"#
        ),
    );
    let limits = Limits {
        max_custom_fields: 4,
        ..Limits::new()
    };
    let preview = parse(xml.as_bytes(), Some(&ImportedSecret::from("p")), &limits).unwrap();
    let node = find(&preview, "a");
    assert_eq!(node.custom_fields.len(), 4);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::LimitReached {
                limit: "custom_fields".to_owned()
            })
    );
    assert_eq!(
        Finding::LimitReached {
            limit: "custom_fields".to_owned()
        }
        .severity(),
        Severity::Warning
    );
}
