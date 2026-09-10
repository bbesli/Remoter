//! The validation rules that need the whole tree: credential existence, kind
//! and purpose, gateway hop targets, and group membership.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use remoter_core::{
    ConnectionProps, CoreError, CredentialProps, CredentialRef, GatewayHop, GroupLayout,
    GroupProps, Inherited, Node, NodeId, NodeKind, NodeRef, ProtocolId, SecretKind, Tree,
    ValidationError,
};

const NOW: i64 = 1_760_000_000_000;

fn folder(name: &str) -> Node {
    Node::new(NodeKind::folder(), name, NOW)
}

fn connection(name: &str, protocol: &str, host: &str) -> Node {
    Node::new(
        NodeKind::Connection(ConnectionProps::new(protocol, host).unwrap()),
        name,
        NOW,
    )
}

fn credential(name: &str, allowed: &[&str]) -> Node {
    let mut props = CredentialProps::new(
        name,
        SecretKind::Agent {
            comment_filter: None,
        },
    );
    props.allowed_protocols = allowed
        .iter()
        .map(|id| ProtocolId::new(*id).unwrap())
        .collect();
    Node::new(NodeKind::Credential(props), name, NOW)
}

fn connection_props(node: &mut Node) -> &mut ConnectionProps {
    match &mut node.kind {
        NodeKind::Connection(props) => props,
        _ => panic!("not a connection"),
    }
}

// --- credential references -----------------------------------------------

#[test]
fn a_reference_to_a_credential_in_the_vault_is_accepted() {
    let mut tree = Tree::new();
    let cred = credential("svc-deploy", &[]);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(cred_id));
    tree.insert(conn).unwrap();

    assert!(tree.validate_references(conn_id).is_ok());
    assert!(tree.validate_all().is_empty());
}

#[test]
fn a_reference_to_a_credential_outside_the_vault_is_rejected() {
    let mut tree = Tree::new();
    let foreign = NodeId::new();
    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(foreign));
    tree.insert(conn).unwrap();

    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialUnknown {
            credential: foreign
        })
    );
    assert_eq!(tree.validate_all().len(), 1);
}

#[test]
fn a_credential_reference_pointing_at_a_folder_is_rejected() {
    let mut tree = Tree::new();
    let not_a_credential = folder("Datacentre");
    let folder_id = not_a_credential.id;
    tree.insert(not_a_credential).unwrap();

    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(folder_id));
    tree.insert(conn).unwrap();

    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialNotACredential {
            credential: folder_id
        })
    );
}

#[test]
fn a_tombstoned_credential_is_not_a_validation_failure() {
    // The user already confirmed the delete. The missing credential is
    // reported at connect time, by name, rather than blocking every edit of
    // the connection until it is replaced.
    let mut tree = Tree::new();
    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).credential =
        Inherited::Explicit(CredentialRef::deleted(NodeId::new(), "svc-deploy"));
    tree.insert(conn).unwrap();

    assert!(tree.validate_references(conn_id).is_ok());
}

// --- credential purpose --------------------------------------------------

#[test]
fn an_unrestricted_credential_may_be_used_by_any_protocol() {
    let mut tree = Tree::new();
    let cred = credential("svc-deploy", &[]);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    for (index, protocol) in ["ssh", "rdp", "vnc"].iter().enumerate() {
        let mut conn = connection(&format!("host-{index}"), protocol, "host.example");
        let conn_id = conn.id;
        connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(cred_id));
        tree.insert(conn).unwrap();
        assert!(tree.validate_references(conn_id).is_ok());
    }
}

#[test]
fn a_restricted_credential_is_rejected_for_another_protocol() {
    let mut tree = Tree::new();
    let cred = credential("CONTOSO-admin", &["rdp"]);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    let mut allowed = connection("ctso-dc01", "rdp", "ctso-dc01");
    let allowed_id = allowed.id;
    connection_props(&mut allowed).credential = Inherited::Explicit(CredentialRef::live(cred_id));
    tree.insert(allowed).unwrap();
    assert!(tree.validate_references(allowed_id).is_ok());

    let mut refused = connection("web-01", "ssh", "web-01.example");
    let refused_id = refused.id;
    connection_props(&mut refused).credential = Inherited::Explicit(CredentialRef::live(cred_id));
    tree.insert(refused).unwrap();
    assert_eq!(
        tree.validate_references(refused_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialPurpose {
            credential: cred_id,
            protocol: "ssh".to_owned()
        })
    );
}

#[test]
fn the_purpose_restriction_applies_to_an_inherited_credential() {
    // The whole point: a credential picked up from a shared parent folder is
    // the one that will actually be used, so it is the one that is checked.
    let mut tree = Tree::new();
    let mut root = folder("Customer sites");
    let root_id = root.id;

    let cred = credential("CONTOSO-admin", &["rdp"]).under(root_id, 0);
    let cred_id = cred.id;

    if let NodeKind::Folder(props) = &mut root.kind {
        props.credential = Inherited::Explicit(CredentialRef::live(cred_id));
    }
    tree.insert(root).unwrap();
    tree.insert(cred).unwrap();

    let ssh = connection("web-01", "ssh", "web-01.example").under(root_id, 1);
    let ssh_id = ssh.id;
    tree.insert(ssh).unwrap();

    // The folder itself is fine — it declares no protocol.
    assert!(tree.validate_references(root_id).is_ok());
    // The connection beneath it is not.
    assert_eq!(
        tree.validate_references(ssh_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialPurpose {
            credential: cred_id,
            protocol: "ssh".to_owned()
        })
    );
}

// --- gateway chains ------------------------------------------------------

#[test]
fn a_gateway_hop_must_be_a_connection_in_the_vault() {
    let mut tree = Tree::new();
    let jump = connection("jump", "ssh", "jump.acme.io");
    let jump_id = jump.id;
    tree.insert(jump).unwrap();
    let not_a_connection = folder("Datacentre");
    let folder_id = not_a_connection.id;
    tree.insert(not_a_connection).unwrap();

    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).gateway =
        Inherited::Explicit(vec![GatewayHop::new(jump_id)].into_iter().collect());
    tree.insert(conn).unwrap();
    assert!(tree.validate_references(conn_id).is_ok());

    let mut edited = tree.get(conn_id).unwrap().clone();
    connection_props(&mut edited).gateway =
        Inherited::Explicit(vec![GatewayHop::new(folder_id)].into_iter().collect());
    tree.update(edited).unwrap();
    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::GatewayHopNotAConnection { hop: folder_id })
    );

    let missing = NodeId::new();
    let mut edited = tree.get(conn_id).unwrap().clone();
    connection_props(&mut edited).gateway =
        Inherited::Explicit(vec![GatewayHop::new(missing)].into_iter().collect());
    tree.update(edited).unwrap();
    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::GatewayHopUnknown { hop: missing })
    );
}

#[test]
fn a_connection_cannot_be_its_own_gateway() {
    let mut tree = Tree::new();
    let conn = connection("jump", "ssh", "jump.acme.io");
    let conn_id = conn.id;
    tree.insert(conn).unwrap();

    let mut edited = tree.get(conn_id).unwrap().clone();
    connection_props(&mut edited).gateway =
        Inherited::Explicit(vec![GatewayHop::new(conn_id)].into_iter().collect());
    tree.update(edited).unwrap();

    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::GatewayCycle { hop: conn_id })
    );
}

#[test]
fn a_hop_credential_is_checked_against_the_hop_protocol() {
    let mut tree = Tree::new();
    let cred = credential("CONTOSO-admin", &["rdp"]);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    let jump = connection("jump", "ssh", "jump.acme.io");
    let jump_id = jump.id;
    tree.insert(jump).unwrap();

    let mut conn = connection("web-01", "ssh", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).gateway = Inherited::Explicit(
        vec![GatewayHop::with_credential(
            jump_id,
            CredentialRef::live(cred_id),
        )]
        .into_iter()
        .collect(),
    );
    tree.insert(conn).unwrap();

    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialPurpose {
            credential: cred_id,
            protocol: "ssh".to_owned()
        })
    );
}

#[test]
fn an_inherited_gateway_chain_is_checked_too() {
    let mut tree = Tree::new();
    let mut root = folder("Datacentre");
    let root_id = root.id;
    let missing = NodeId::new();
    if let NodeKind::Folder(props) = &mut root.kind {
        props.gateway = Inherited::Explicit(vec![GatewayHop::new(missing)].into_iter().collect());
    }
    tree.insert(root).unwrap();

    let conn = connection("web-01", "ssh", "web-01.example").under(root_id, 0);
    let conn_id = conn.id;
    tree.insert(conn).unwrap();

    assert_eq!(
        tree.validate_references(conn_id).unwrap_err(),
        CoreError::Validation(ValidationError::GatewayHopUnknown { hop: missing })
    );
}

// --- group membership ----------------------------------------------------

#[test]
fn group_members_must_exist() {
    let mut tree = Tree::new();
    let member = connection("web-01", "ssh", "web-01.example");
    let member_id = member.id;
    tree.insert(member).unwrap();

    let group = Node::new(
        NodeKind::Group(GroupProps {
            members: vec![NodeRef::live(member_id)],
            layout: GroupLayout::Tabs,
            broadcast: false,
        }),
        "Web tier",
        NOW,
    );
    let group_id = group.id;
    tree.insert(group).unwrap();
    assert!(tree.validate_references(group_id).is_ok());

    let missing = NodeId::new();
    let mut edited = tree.get(group_id).unwrap().clone();
    if let NodeKind::Group(props) = &mut edited.kind {
        props.members.push(NodeRef::live(missing));
    }
    tree.update(edited).unwrap();
    assert_eq!(
        tree.validate_references(group_id).unwrap_err(),
        CoreError::Validation(ValidationError::GroupMemberUnknown { member: missing })
    );
}

#[test]
fn validate_all_reports_every_offending_node() {
    let mut tree = Tree::new();
    let missing = NodeId::new();

    for index in 0..3 {
        let mut conn = connection(&format!("host-{index}"), "ssh", "host.example");
        connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(missing));
        tree.insert(conn).unwrap();
    }
    let ok = connection("host-ok", "ssh", "host.example");
    tree.insert(ok).unwrap();

    let failures = tree.validate_all();
    assert_eq!(failures.len(), 3);
    assert!(failures.iter().all(|(_, error)| matches!(
        error,
        CoreError::Validation(ValidationError::CredentialUnknown { .. })
    )));
}
