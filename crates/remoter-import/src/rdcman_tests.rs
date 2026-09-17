//! Tests for the Remote Desktop Connection Manager importer.

#![allow(
    clippy::panic,
    clippy::unwrap_used,
    reason = "test code, per docs/development/coding-standards.md"
)]

use remoter_core::SecretKind;

use super::*;
use crate::preview::{PreviewCredential, PreviewKind as Kind};

/// What RDCMan 2.93 writes, with the blobs shortened: a file-scoped profile, a
/// folder that sets an account for everything under it, and the cases that
/// each need a decision.
const LAB: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan programVersion="2.93" schemaVersion="3">
  <file>
    <credentialsProfiles>
      <credentialsProfile inherit="None">
        <profileName scope="Local">Operators</profileName>
        <userName>ops</userName>
        <password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAprofile</password>
        <domain>CONTOSO</domain>
      </credentialsProfile>
    </credentialsProfiles>
    <properties>
      <expanded>True</expanded>
      <name>Lab</name>
    </properties>
    <group>
      <properties>
        <expanded>True</expanded>
        <name>Domain controllers</name>
        <comment>Both sites</comment>
      </properties>
      <logonCredentials inherit="None">
        <profileName scope="Local">Custom</profileName>
        <userName>CONTOSO\administrator</userName>
        <password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAinline</password>
        <domain />
      </logonCredentials>
      <connectionSettings inherit="None">
        <connectToConsole>True</connectToConsole>
        <startProgram />
        <workingDir />
        <port>3390</port>
        <loadBalanceInfo />
      </connectionSettings>
      <server>
        <properties>
          <displayName>DC01</displayName>
          <name>dc01.contoso.local</name>
        </properties>
      </server>
      <server>
        <properties>
          <name>dc02.contoso.local:3391</name>
        </properties>
        <remoteDesktop inherit="None">
          <sameSizeAsClientArea>False</sameSizeAsClientArea>
          <fullScreen>False</fullScreen>
          <colorDepth>24</colorDepth>
          <size>1600 x 900</size>
        </remoteDesktop>
      </server>
    </group>
    <group>
      <properties>
        <name>Apps</name>
      </properties>
      <server>
        <properties>
          <displayName>Billing</displayName>
          <name>billing.contoso.local</name>
        </properties>
        <logonCredentials inherit="None">
          <profileName scope="File">Operators</profileName>
        </logonCredentials>
        <gatewaySettings inherit="None">
          <enabled>True</enabled>
          <hostName>rdgw.contoso.com</hostName>
          <logonMethod>Any</logonMethod>
          <localBypass>False</localBypass>
          <credSharing>False</credSharing>
          <profileName scope="Local">Custom</profileName>
          <userName>gw</userName>
          <password>AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAAgateway</password>
          <domain />
        </gatewaySettings>
      </server>
      <server>
        <properties>
          <displayName>Payroll</displayName>
          <name>payroll.contoso.local</name>
        </properties>
        <logonCredentials inherit="None">
          <profileName scope="Local">Helpdesk</profileName>
        </logonCredentials>
      </server>
      <server>
        <properties>
          <displayName>Broken</displayName>
          <name>not a host</name>
        </properties>
      </server>
      <smartGroup>
        <properties>
          <name>Everything web</name>
        </properties>
        <ruleGroup operator="All">
          <rule>
            <property>DisplayName</property>
            <operator>Matches</operator>
            <value>web</value>
          </rule>
        </ruleGroup>
      </smartGroup>
    </group>
  </file>
  <connected />
  <favorites />
  <recentlyUsed />
</RDCMan>
"#;

/// RDCMan 2.2: settings beside the name, and a password stored in the clear.
const OLD: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<RDCMan schemaVersion="1">
  <version>2.2</version>
  <file>
    <properties>
      <name>Old estate</name>
      <expanded>True</expanded>
      <comment />
      <logonCredentials inherit="FromParent" />
      <connectionSettings inherit="FromParent" />
    </properties>
    <server>
      <name>legacy01</name>
      <displayName>Legacy 01</displayName>
      <comment>Keep until 2027</comment>
      <logonCredentials inherit="None">
        <userName>admin</userName>
        <password storeAsClearText="True">hunter2</password>
        <domain>LEGACY</domain>
      </logonCredentials>
      <connectionSettings inherit="FromParent" />
    </server>
  </file>
</RDCMan>
"#;

fn preview_of(document: &str) -> ImportPreview {
    parse(document.as_bytes(), &Limits::new()).unwrap()
}

fn node<'a>(preview: &'a ImportPreview, name: &str) -> &'a PreviewNode {
    preview
        .nodes()
        .iter()
        .find(|node| node.name == name)
        .unwrap_or_else(|| panic!("no node named {name} in {:?}", preview.summaries()))
}

fn connection<'a>(preview: &'a ImportPreview, name: &str) -> &'a ConnectionProps {
    let Kind::Connection(props) = &node(preview, name).kind else {
        panic!("{name} is not a connection");
    };
    props
}

fn folder<'a>(preview: &'a ImportPreview, name: &str) -> &'a FolderProps {
    let Kind::Folder(props) = &node(preview, name).kind else {
        panic!("{name} is not a folder");
    };
    props
}

fn credential_of<'a>(
    preview: &'a ImportPreview,
    reference: &Inherited<CredentialRef>,
) -> &'a PreviewCredential {
    let Inherited::Explicit(reference) = reference else {
        panic!("the credential is inherited");
    };
    preview
        .nodes()
        .iter()
        .find_map(|node| match &node.kind {
            Kind::Credential(credential) if node.id == reference.id() => Some(credential),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no credential {reference:?}"))
}

#[test]
fn the_document_becomes_its_own_tree() {
    let preview = preview_of(LAB);
    let lab = node(&preview, "Lab");
    assert_eq!(lab.parent_id, None);
    let controllers = node(&preview, "Domain controllers");
    assert_eq!(controllers.parent_id, Some(lab.id));
    assert_eq!(controllers.description, "Both sites");
    assert_eq!(node(&preview, "DC01").parent_id, Some(controllers.id));
    // No display name: the server is named after its address.
    assert_eq!(
        node(&preview, "dc02.contoso.local:3391").parent_id,
        Some(controllers.id)
    );
    assert_eq!(connection(&preview, "DC01").protocol.as_str(), "rdp");
    assert_eq!(connection(&preview, "DC01").host, "dc01.contoso.local");
}

#[test]
fn a_setting_made_once_on_a_group_stays_on_the_group() {
    let preview = preview_of(LAB);
    let controllers = folder(&preview, "Domain controllers");
    assert_eq!(controllers.port, Inherited::Explicit(3390));
    let account = credential_of(&preview, &controllers.credential);
    assert_eq!(account.username, "administrator");
    assert_eq!(account.domain.as_deref(), Some("CONTOSO"));
    assert!(matches!(
        account.secret,
        PreviewSecret::PasswordNotCarried(_)
    ));

    let dc01 = connection(&preview, "DC01");
    assert_eq!(dc01.port, Inherited::Inherit);
    assert_eq!(dc01.credential, Inherited::Inherit);
    // A port in the server's own name is its own.
    assert_eq!(
        connection(&preview, "dc02.contoso.local:3391").port,
        Inherited::Explicit(3391)
    );
    assert_eq!(
        node(&preview, "Domain controllers")
            .custom_fields
            .get("rdcman.connectionSettings.connectToConsole")
            .map(String::as_str),
        Some("True")
    );
}

#[test]
fn a_desktop_size_becomes_the_adapters_setting() {
    let preview = preview_of(LAB);
    let dc02 = connection(&preview, "dc02.contoso.local:3391");
    assert_eq!(dc02.settings.get("desktop_width"), Some("1600"));
    assert_eq!(dc02.settings.get("desktop_height"), Some("900"));
}

#[test]
fn a_profile_in_the_file_is_one_credential_and_a_local_one_is_named_as_missing() {
    let preview = preview_of(LAB);
    let billing = credential_of(&preview, &connection(&preview, "Billing").credential);
    assert_eq!(billing.username, "ops");
    assert_eq!(billing.domain.as_deref(), Some("CONTOSO"));

    let payroll = credential_of(&preview, &connection(&preview, "Payroll").credential);
    assert_eq!(payroll.username, "");
    assert!(matches!(
        payroll.secret,
        PreviewSecret::PasswordNotCarried(_)
    ));
    assert!(node(&preview, "Helpdesk credentials").parent_id.is_some());
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::CredentialProfileMissing {
                item: "Payroll".to_owned(),
                profile: "Helpdesk".to_owned(),
            })
    );
}

#[test]
fn no_saved_password_comes_across_and_the_report_counts_them() {
    let preview = preview_of(LAB);
    assert_eq!(preview.report().counts().secrets, 0);
    // The group's inline password and the file's profile. The gateway's is a
    // different field and is reported on its own.
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::ProtectedPasswordsNotCarried { count: 2 })
    );
    for node in preview.nodes() {
        assert!(!node.needs_sealing(), "{} carries a secret", node.name);
        for value in node.custom_fields.values() {
            assert!(!value.contains("AQAAANCM"), "{} keeps a blob", node.name);
        }
    }
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretNotMapped {
                item: "Billing".to_owned(),
                field: "gatewaySettings.password".to_owned(),
            })
    );
}

#[test]
fn a_gateway_is_warned_about_and_its_host_kept() {
    let preview = preview_of(LAB);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::RdGatewayNotSupported {
                item: "Billing".to_owned(),
                host: "rdgw.contoso.com".to_owned(),
            })
    );
    let billing = node(&preview, "Billing");
    assert_eq!(
        billing
            .custom_fields
            .get("rdcman.gatewaySettings.hostName")
            .map(String::as_str),
        Some("rdgw.contoso.com")
    );
}

#[test]
fn what_cannot_be_a_connection_is_left_out_by_name() {
    let preview = preview_of(LAB);
    assert_eq!(preview.report().counts().skipped, 2);
    let findings = preview.report().findings();
    assert!(findings.contains(&Finding::SkippedItem {
        item: "Broken".to_owned(),
        reason: SkipReason::UnusableHost,
    }));
    assert!(findings.contains(&Finding::SkippedItem {
        item: "Everything web".to_owned(),
        reason: SkipReason::UnsupportedKind,
    }));
    assert!(
        preview
            .nodes()
            .iter()
            .all(|node| node.name != "Everything web")
    );
}

#[test]
fn schema_one_is_read_and_its_clear_text_password_imported() {
    let preview = preview_of(OLD);
    let root = folder(&preview, "Old estate");
    assert_eq!(root.credential, Inherited::Inherit);
    assert_eq!(node(&preview, "Legacy 01").description, "Keep until 2027");
    let legacy = connection(&preview, "Legacy 01");
    assert_eq!(legacy.host, "legacy01");
    let account = credential_of(&preview, &legacy.credential);
    assert_eq!(account.username, "admin");
    assert_eq!(account.domain.as_deref(), Some("LEGACY"));
    let PreviewSecret::Password(password) = &account.secret else {
        panic!("the clear-text password did not come across");
    };
    assert_eq!(password.expose(), "hunter2");
    assert_eq!(preview.report().counts().secrets, 1);
    assert!(
        preview
            .report()
            .findings()
            .contains(&Finding::SecretsRecovered { count: 1 })
    );
}

#[test]
fn every_password_credential_becomes_a_node_that_asks() {
    let (nodes, _) = preview_of(LAB).into_parts();
    for node in nodes {
        if node.holds_password() {
            let built = node.into_node(0, Some(vec![0])).unwrap();
            assert!(matches!(
                built.kind,
                remoter_core::NodeKind::Credential(remoter_core::CredentialProps {
                    secret: SecretKind::Password { .. },
                    ..
                })
            ));
        }
    }
}

#[test]
fn something_else_is_refused() {
    assert!(matches!(
        parse(b"<Connections Name=\"x\"/>", &Limits::new()),
        Err(ImportError::WrongFormat { .. })
    ));
    assert!(matches!(
        parse(b"<RDCMan schemaVersion=\"3\"></RDCMan>", &Limits::new()),
        Err(ImportError::WrongFormat { .. })
    ));
    assert!(matches!(
        parse(
            b"<!DOCTYPE r [<!ENTITY x \"y\">]><RDCMan><file/></RDCMan>",
            &Limits::new()
        ),
        Err(ImportError::DoctypeRefused)
    ));
}

#[test]
fn the_bounds_hold() {
    let long = format!(
        "<RDCMan><file><properties><name>{}</name></properties></file></RDCMan>",
        "a".repeat(5000)
    );
    assert!(matches!(
        parse(long.as_bytes(), &Limits::small()),
        Err(ImportError::ValueTooLong { .. })
    ));
    let deep = format!(
        "<RDCMan><file>{}{}</file></RDCMan>",
        "<group>".repeat(40),
        "</group>".repeat(40)
    );
    assert!(matches!(
        parse(deep.as_bytes(), &Limits::small()),
        Err(ImportError::TooDeep { .. })
    ));
}

#[test]
fn truncation_anywhere_is_a_refusal_or_a_smaller_tree_never_a_panic() {
    for cut in 0..LAB.len() {
        if LAB.is_char_boundary(cut) {
            let _ = parse(&LAB.as_bytes()[..cut], &Limits::new());
        }
    }
}
