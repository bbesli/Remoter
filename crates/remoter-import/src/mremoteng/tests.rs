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
use crate::error::XmlProblem;
use crate::preview::PreviewKind as Kind;
use crate::report::Severity;

const GCM: CipherMode = CipherMode::Gcm { iterations: 1000 };

/// Wraps a body in the root element mRemoteNG writes.
///
/// Namespaced, because that is what is in the file. `XmlRootNodeSerializer`
/// builds the root as `XNamespace "http://mremoteng.org" + "Connections"` with
/// the prefix `mrng` declared beside it, and has since 1.76 — so a fixture
/// spelled `<Connections>` is a fixture of a file nobody has.
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
<mrng:Connections xmlns:mrng="http://mremoteng.org" Name="Acme Production" Export="false" \
EncryptionEngine="AES" BlockCipherMode="{mode}" KdfIterations="{iterations}" \
FullFileEncryption="{full_file}" Protected="{protected}" ConfVersion="2.6">{body}\
</mrng:Connections>"#
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
    preview_bytes(xml.as_bytes(), password)
}

/// The same, for a fixture that is bytes rather than text — one with a
/// byte-order mark on the front, as a real export has.
fn preview_bytes(bytes: &[u8], password: Option<&str>) -> ImportPreview {
    let password = password.map(ImportedSecret::from);
    parse(bytes, password.as_ref(), &Limits::new()).unwrap()
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
fn a_document_that_is_not_a_confcons_is_refused_by_name() {
    // Choosing the wrong file is the ordinary way to meet this, so the refusal
    // says what the file turned out to be rather than only what it was not.
    // "This is not an mRemoteNG confCons.xml" leaves someone holding a Royal TS
    // export with nothing to go on.
    let ImportError::XmlNotWellFormed { problem, location } = refusal(
        b"<?xml version=\"1.0\"?>\n<RoyalDocument><Object/></RoyalDocument>",
        None,
    ) else {
        panic!("expected a located refusal");
    };
    assert_eq!(
        problem,
        XmlProblem::UnexpectedRoot {
            found: "RoyalDocument".to_owned(),
            expected: "Connections",
        }
    );
    assert_eq!(location.line, 2);
    // The element is already in the sentence; repeating it in the location
    // would say it twice.
    assert_eq!(location.element, None);

    let ImportError::XmlNotWellFormed { problem, .. } = refusal(b"", None) else {
        panic!("expected a located refusal");
    };
    assert_eq!(
        problem,
        XmlProblem::NoRootElement {
            expected: "Connections",
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

// ------------------------------------------------ a real mRemoteNG export ---
//
// Everything above builds the *shape* of a confCons.xml. What follows builds
// the *size* of one, because the two are not the same test: mRemoteNG writes
// around a hundred and fifty attributes on every connection, two-thirds of them
// `Inherit*` flags, in a UTF-8-with-BOM file with CRLF line endings and an XML
// declaration on the first line. The attribute ceiling, the preservation pass,
// the inheritance rules and the BOM strip all have to survive that, and none of
// them is exercised by a five-attribute node.
//
// The attribute list is mRemoteNG 1.77's, in its own order and with its own
// spellings and default values — `Colors="Colors16Bit"`, `RedirectSound="DoNotPlay"`,
// `RDGatewayUsageMethod="Never"` — so that a mapping written against a
// simplified idea of the format fails here rather than on the owner's machine.

/// The non-inheritable half of an mRemoteNG 1.77 connection node.
const RDP_SETTINGS: &str = concat!(
    r#" Icon="mRemoteNG" Panel="General" PuttySession="Default Settings""#,
    r#" ConnectToConsole="false" UseCredSsp="true" UseRestrictedAdmin="false""#,
    r#" UseRCG="false" UseVmId="false" UseEnhancedMode="false" VmId="""#,
    r#" RenderingEngine="IE" ICAEncryptionStrength="EncrBasic""#,
    r#" RDPAuthenticationLevel="NoAuth" RDPMinutesToIdleTimeout="0""#,
    r#" RDPAlertIdleTimeout="false" LoadBalanceInfo="" Colors="Colors16Bit""#,
    r#" Resolution="FitToWindow" AutomaticResize="true" DisplayWallpaper="false""#,
    r#" DisplayThemes="false" EnableFontSmoothing="false""#,
    r#" EnableDesktopComposition="false" DisableFullWindowDrag="false""#,
    r#" DisableMenuAnimations="false" DisableCursorShadow="false""#,
    r#" DisableCursorBlinking="false" CacheBitmaps="false""#,
    r#" RedirectDiskDrives="false" RedirectDiskDrivesCustom="""#,
    r#" RedirectPrinters="false" RedirectClipboard="true" RedirectPorts="false""#,
    r#" RedirectSmartCards="false" RedirectSound="DoNotPlay""#,
    r#" RedirectAudioCapture="false" SoundQuality="Dynamic" RedirectKeys="false""#,
    r#" Connected="false" PreExtApp="" PostExtApp="" MacAddress="" UserField="""#,
    r#" ExtApp="" VNCCompression="CompNone" VNCEncoding="EncHextile""#,
    r#" VNCAuthMode="AuthVNC" VNCProxyType="ProxyNone" VNCProxyIP="""#,
    r#" VNCProxyPort="0" VNCProxyUsername="" VNCProxyPassword="""#,
    r#" VNCColors="ColNormal" VNCSmartSizeMode="SmartSAspect" VNCViewOnly="false""#,
    r#" RDGatewayUsageMethod="Never" RDGatewayHostname="""#,
    r#" RDGatewayUseConnectionCredentials="Yes" RDGatewayUsername="""#,
    r#" RDGatewayPassword="" RDGatewayDomain="" OpeningCommand="" SSHOptions="""#,
    r#" EC2InstanceId="" EC2Region="""#,
);

/// The `Inherit*` half, which mRemoteNG writes in full on every node.
///
/// `inherited` selects the four the mapping reads — port, username, password
/// and domain — so one function produces both a node that sets its own
/// credential and a node that takes its parent's.
fn inherit_flags(inherited: bool) -> String {
    let value = if inherited { "true" } else { "false" };
    let mut out = String::new();
    for name in [
        "CacheBitmaps",
        "Colors",
        "Description",
        "DisplayThemes",
        "DisplayWallpaper",
        "EnableFontSmoothing",
        "EnableDesktopComposition",
        "DisableFullWindowDrag",
        "DisableMenuAnimations",
        "DisableCursorShadow",
        "DisableCursorBlinking",
        "Icon",
        "Panel",
        "Protocol",
        "PuttySession",
        "RedirectDiskDrives",
        "RedirectKeys",
        "RedirectPorts",
        "RedirectPrinters",
        "RedirectClipboard",
        "RedirectSmartCards",
        "RedirectSound",
        "SoundQuality",
        "RedirectAudioCapture",
        "Resolution",
        "AutomaticResize",
        "UseConsoleSession",
        "UseCredSsp",
        "UseRestrictedAdmin",
        "UseRCG",
        "UseVmId",
        "UseEnhancedMode",
        "VmId",
        "RenderingEngine",
        "ICAEncryptionStrength",
        "RDPAuthenticationLevel",
        "RDPMinutesToIdleTimeout",
        "RDPAlertIdleTimeout",
        "LoadBalanceInfo",
        "PreExtApp",
        "PostExtApp",
        "MacAddress",
        "UserField",
        "ExtApp",
        "VNCCompression",
        "VNCEncoding",
        "VNCAuthMode",
        "VNCProxyType",
        "VNCProxyIP",
        "VNCProxyPort",
        "VNCProxyUsername",
        "VNCProxyPassword",
        "VNCColors",
        "VNCSmartSizeMode",
        "VNCViewOnly",
        "RDGatewayUsageMethod",
        "RDGatewayHostname",
        "RDGatewayUseConnectionCredentials",
        "RDGatewayUsername",
        "RDGatewayPassword",
        "RDGatewayDomain",
        "SSHTunnelConnectionName",
        "OpeningCommand",
        "SSHOptions",
        "EC2InstanceId",
        "EC2Region",
    ] {
        out.push_str(&format!(r#" Inherit{name}="false""#));
    }
    // The four the mapping actually reads.
    for name in ["Port", "Username", "Password", "Domain"] {
        out.push_str(&format!(r#" Inherit{name}="{value}""#));
    }
    out
}

/// One connection node with the attribute set mRemoteNG really writes.
fn real_node(
    name: &str,
    host: &str,
    protocol: &str,
    port: &str,
    credential: Option<(&str, &str, &str)>,
) -> String {
    let (username, domain, password) = credential.unwrap_or(("", "", ""));
    format!(
        r#"<Node Name="{name}" Type="Connection" Descr="" Id="bb1a5c9e-{port}-4f0e-9c21-8b0f2a1d3e44" Username="{username}" Domain="{domain}" Password="{password}" Hostname="{host}" Protocol="{protocol}" SSHTunnelConnectionName="" Port="{port}"{RDP_SETTINGS}{flags} />"#,
        flags = inherit_flags(credential.is_none()),
    )
}

/// A `confCons.xml` as mRemoteNG writes one on Windows.
///
/// BOM, CRLF, XML declaration, a container that carries the credential and the
/// port for everything under it, and connections that inherit them — the estate
/// shape `docs/architecture/data-model.md` describes, at the fidelity the tool
/// actually emits.
fn real_export(cipher: CipherMode, file_password: &str) -> Vec<u8> {
    let svc = secret(cipher, file_password, "hunter2", 1);
    let admin = secret(cipher, file_password, "Tr0ub4dor&3", 2);
    let body = format!(
        "\r\n  <Node Name=\"Datacentre EU-West\" Type=\"Container\" Expanded=\"true\" \
Descr=\"Frankfurt\" Icon=\"Server\" Panel=\"General\" Username=\"svc-deploy\" Domain=\"\" \
Password=\"{svc}\" Hostname=\"\" Protocol=\"RDP\" Port=\"3389\">\r\n    {inherits}\r\n    \
{explicit}\r\n  </Node>\r\n  {standalone}\r\n",
        inherits = real_node("web-01", "web-01.eu.acme.internal", "RDP", "3389", None),
        explicit = real_node(
            "web-02",
            "web-02.eu.acme.internal",
            "SSH2",
            "2022",
            Some(("root", "", &admin)),
        ),
        standalone = real_node(
            "SRV-DC01",
            "srv-dc01.corp.local",
            "RDP",
            "3389",
            Some(("administrator", "CORP", &admin)),
        ),
    );
    let document = document(cipher, file_password, false, &body).replace('\n', "\r\n");
    // mRemoteNG writes UTF-8 with a byte-order mark. A reader that treats it as
    // content sees `<?xml` preceded by three bytes of nothing and refuses the
    // file, which is one of the ways this import can fail before it starts.
    let mut bytes = "\u{feff}".as_bytes().to_vec();
    bytes.extend_from_slice(document.as_bytes());
    bytes
}

#[test]
fn a_real_mremoteng_export_comes_in_whole() {
    let bytes = real_export(GCM, DEFAULT_PASSWORD);
    // Detection has to recognise it too: the wizard preselects the format from
    // this, and a file it cannot place is a file the user has to place by hand.
    assert_eq!(
        crate::detect(&bytes),
        Some(crate::SourceFormat::MRemoteNg),
        "a real export is not recognised as one"
    );

    let info = inspect(&bytes, &Limits::new()).unwrap();
    assert_eq!(info.name, "Acme Production");
    assert_eq!(info.conf_version.as_deref(), Some("2.6"));
    assert!(
        !info.password_required,
        "the default password should open it"
    );

    let preview = parse(&bytes, None, &Limits::new()).unwrap();
    let counts = preview.report().counts();
    assert_eq!(counts.connections, 3);
    assert_eq!(
        counts.skipped, 0,
        "nothing in a real export should be refused"
    );
    // One container, plus the folder the credentials land in.
    assert_eq!(counts.folders, 2);
    // Three accounts: the container's service account and two administrators
    // that differ by domain. Two of them share a password and are still two
    // credentials, because a credential is an account and not a password.
    assert_eq!(counts.secrets, 3);

    // The estate arrives with its structure intact rather than flattened: the
    // container keeps the port and the credential, and the node that inherits
    // them holds neither.
    let Kind::Folder(folder) = &find(&preview, "Datacentre EU-West").kind else {
        panic!("the container did not become a folder");
    };
    assert_eq!(folder.port, Inherited::Explicit(3389));
    assert!(matches!(folder.credential, Inherited::Explicit(_)));
    let web01 = connection(&preview, "web-01");
    assert_eq!(web01.port, Inherited::Inherit);
    assert_eq!(web01.credential, Inherited::Inherit);
    let web02 = connection(&preview, "web-02");
    assert_eq!(web02.port, Inherited::Explicit(2022));
    assert!(matches!(web02.credential, Inherited::Explicit(_)));

    // The RDP settings the domain model has no home for are kept verbatim…
    let dc01 = find(&preview, "SRV-DC01");
    assert_eq!(
        dc01.custom_fields
            .get("mremoteng.RDGatewayUsageMethod")
            .map(String::as_str),
        Some("Never")
    );
    assert_eq!(
        dc01.custom_fields
            .get("mremoteng.Colors")
            .map(String::as_str),
        Some("Colors16Bit")
    );
    // …and the `Inherit*` flags themselves are state, not settings, so none of
    // them is copied in as data.
    assert!(
        dc01.custom_fields
            .keys()
            .all(|key| !key.contains("Inherit")),
        "inheritance flags were preserved as settings"
    );
    // A node that inherits gets nothing copied onto it, which is the whole
    // point of reading the flags rather than flattening.
    assert!(
        !find(&preview, "web-01")
            .custom_fields
            .contains_key("mremoteng.Port"),
        "an inherited value was flattened onto the node that inherits it"
    );

    // And the file's protection is named for what it was.
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::DefaultFilePassword),
        "a file on the published default password must say so"
    );
    // And it becomes a tree the domain model accepts, which is what the commit
    // does with it. A preview that parses and then fails to insert would fail
    // after the vault is open, which is the worst place for it.
    let expected = preview.nodes().len();
    let (nodes, _) = preview.into_parts();
    let nodes: Vec<Node> = nodes
        .into_iter()
        .map(|node| {
            // Standing in for the vault's sealing call.
            let sealed = node.needs_sealing().then(|| vec![0x5a; 32]);
            node.into_node(1_700_000_000_000, sealed).unwrap()
        })
        .collect();
    assert_eq!(Tree::from_nodes(nodes).unwrap().len(), expected);
}

#[test]
fn a_real_export_the_owner_put_a_password_on_asks_for_it_once() {
    let bytes = real_export(GCM, "correct horse battery staple");

    // The header alone is enough to know the wizard has to ask.
    let info = inspect(&bytes, &Limits::new()).unwrap();
    assert!(info.password_required);

    // Asking is a different answer from being told the password is wrong: one
    // is a field to fill in, the other is a field to fill in *again*.
    assert_eq!(refusal(&bytes, None), ImportError::PasswordRequired);
    assert_eq!(refusal(&bytes, Some("hunter2")), ImportError::WrongPassword);

    let preview = preview_bytes(&bytes, Some("correct horse battery staple"));
    assert_eq!(preview.report().counts().connections, 3);
    assert_eq!(preview.report().counts().secrets, 3);
    // A file with a real password is not the exposed case, so it is not named
    // as one.
    assert!(
        !preview
            .report()
            .findings()
            .contains(&Finding::DefaultFilePassword)
    );
}

#[test]
fn a_legacy_cbc_export_is_read_and_its_weakness_named() {
    // mRemoteNG before 1.75, which plenty of estates are still exported from.
    let bytes = real_export(CipherMode::Cbc, DEFAULT_PASSWORD);
    let preview = parse(&bytes, None, &Limits::new()).unwrap();
    assert_eq!(preview.report().counts().connections, 3);
    assert_eq!(preview.report().counts().secrets, 3);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::LegacyCbcEncryption)
    );
}

#[test]
fn a_password_attribute_that_was_never_encrypted_is_reported_not_stored() {
    // The other half of "both forms of the password attribute": a Password that
    // is not ciphertext at all. It cannot be told from a damaged ciphertext —
    // and guessing would put a base64 blob in the vault as somebody's password
    // — so the connection comes in without it and the report names the field.
    let body = r#"<Node Name="srv02" Type="Connection" Hostname="srv02.corp.local" Protocol="RDP" Port="3389" Username="admin" Domain="CORP" Password="Sup3rSecret!" />"#;
    let xml = document(GCM, DEFAULT_PASSWORD, false, body);
    let preview = preview(&xml, None);
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().secrets, 0);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretNotMapped {
                item: "srv02".to_owned(),
                field: "Password".to_owned(),
            }),
        "an unreadable password must be named, not silently dropped"
    );
    // Everything else about the connection survives it.
    assert_eq!(connection(&preview, "srv02").host, "srv02.corp.local");
}

#[test]
fn a_partial_import_counts_and_names_what_did_not_come_in() {
    // The result screen is built from these two: the count says how much of the
    // file is missing from the vault, and the findings say which parts. An
    // import that reported the first without the second would look like a
    // success with a footnote.
    let body = r#"
  <Node Name="good" Type="Connection" Hostname="good.example.com" Protocol="SSH2" />
  <Node Name="SQL_PROD" Type="Connection" Hostname="SQL_PROD" Protocol="RDP" />
  <Node Name="Open the ticket system" Type="ExtApp" Hostname="" Protocol="IntApp" />
"#;
    let xml = document(GCM, DEFAULT_PASSWORD, false, body);
    let preview = preview(&xml, None);
    assert_eq!(preview.report().counts().connections, 1);
    assert_eq!(preview.report().counts().skipped, 2);
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "SQL_PROD".to_owned(),
        reason: SkipReason::UnusableHost,
    }));
    assert!(preview.report().findings().contains(&Finding::SkippedItem {
        item: "Open the ticket system".to_owned(),
        reason: SkipReason::UnsupportedKind,
    }));
}

/// mRemoteNG's export dialog can leave the passwords out, and an administrator
/// sending their estate to a colleague usually does. Every `Password` is then
/// the empty string while `Username` and `Domain` are still there, and what has
/// to come across is everything but the secret.
#[test]
fn an_export_written_without_passwords_still_brings_the_accounts() {
    let xml = document(
        GCM,
        DEFAULT_PASSWORD,
        false,
        &r#"
  <Node Name="Datacentre EU-West" Type="Container" Expanded="true" Username="svc-deploy" \
Domain="" Password="" Hostname="" Protocol="SSH2" Port="2222">
    <Node Name="web-01" Type="Connection" Hostname="web-01.eu.acme.internal" Protocol="SSH2" \
Port="22" Username="" Domain="" Password="" InheritPort="true" InheritUsername="true" \
InheritPassword="true" InheritDomain="true" />
  </Node>
  <Node Name="SRV-DC01" Type="Connection" Hostname="srv-dc01.corp.local" Protocol="RDP" \
Port="3389" Username="administrator" Domain="CORP" Password="" />
"#
        .replace("\\\n", ""),
    );
    let preview = preview(&xml, None);

    // Nothing was skipped for want of a password, and nothing was recovered.
    assert_eq!(preview.report().counts().connections, 2);
    assert_eq!(preview.report().counts().skipped, 0);
    assert_eq!(preview.report().counts().secrets, 0);
    assert!(
        !preview
            .report()
            .findings()
            .iter()
            .any(|finding| matches!(finding, Finding::SecretsRecovered { .. })),
        "a file with no passwords in it must not claim to have recovered any"
    );

    // The structure, the hosts and the accounts are all there.
    let dc01 = connection(&preview, "SRV-DC01");
    assert_eq!(dc01.host, "srv-dc01.corp.local");
    assert_eq!(dc01.protocol.as_str(), "rdp");
    assert_eq!(dc01.port, Inherited::Explicit(3389));
    assert!(dc01.credential.is_explicit(), "the account was dropped");
    // The domain travels with the account rather than being dropped: one
    // credential, named the way the file named it.
    let credentials: Vec<&str> = preview
        .nodes()
        .iter()
        .filter(|node| matches!(node.kind, Kind::Credential(_)))
        .map(|node| node.name.as_str())
        .collect();
    assert!(
        credentials.contains(&"CORP\\administrator"),
        "credentials: {credentials:?}"
    );
    assert!(
        credentials.contains(&"svc-deploy"),
        "credentials: {credentials:?}"
    );
    // And none of them claims to hold a password.
    assert!(
        preview.nodes().iter().all(|node| node.secret().is_none()),
        "a file with no passwords in it produced one"
    );

    // And the folder's account still reaches the connection that inherits it.
    assert_eq!(
        connection(&preview, "web-01").credential,
        Inherited::Inherit
    );
    let Kind::Folder(folder) = &find(&preview, "Datacentre EU-West").kind else {
        panic!("the container did not become a folder");
    };
    assert!(folder.credential.is_explicit());
}
