//! Credentials that belong to one connection.
//!
//! Sharing one credential between hundreds of connections is the feature that
//! makes this application worth using at scale. An attached credential is what
//! keeps that from being a tax on the person with one server and a password:
//! the username and the secret they type land on a credential of that
//! connection's own, which is deleted and moved with it and which nothing else
//! may point at.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use remoter_core::{
    ConnectionProps, CoreError, CredentialProps, CredentialRef, Inherited, Node, NodeId, NodeKind,
    Provenance, SecretKind, Tree, ValidationError,
};

const NOW: i64 = 1_760_000_000_000;

fn folder(name: &str) -> Node {
    Node::new(NodeKind::folder(), name, NOW)
}

fn connection(name: &str) -> Node {
    Node::new(
        NodeKind::Connection(ConnectionProps::new("ssh", "web-01.example").unwrap()),
        name,
        NOW,
    )
}

/// A credential of the ordinary, shared kind.
fn shared(name: &str, username: &str) -> Node {
    Node::new(
        NodeKind::Credential(CredentialProps::new(
            username,
            SecretKind::Agent {
                comment_filter: None,
            },
        )),
        name,
        NOW,
    )
}

/// A credential belonging to `connection`.
fn attached(connection: NodeId, name: &str, username: &str) -> Node {
    Node::new(
        NodeKind::Credential(CredentialProps::attached(
            connection,
            username,
            SecretKind::Agent {
                comment_filter: None,
            },
        )),
        name,
        NOW,
    )
}

fn point_at(node: &mut Node, credential: NodeId) {
    match &mut node.kind {
        NodeKind::Connection(props) => {
            props.credential = Inherited::Explicit(CredentialRef::live(credential));
        }
        NodeKind::Folder(props) => {
            props.credential = Inherited::Explicit(CredentialRef::live(credential));
        }
        _ => panic!("only connections and folders authenticate"),
    }
}

// --- resolution ----------------------------------------------------------

#[test]
fn an_attached_credential_resolves_as_the_connections_own_username() {
    let mut tree = Tree::new();
    let mut conn = connection("web-01");
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada");
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    let effective = tree.effective_connection(conn_id).unwrap();
    assert_eq!(effective.username.value.as_deref(), Some("ada"));
    // "Set on this connection", which is what the editor shows next to the
    // field the user typed in.
    assert_eq!(effective.username.provenance, Provenance::Own(conn_id));
    assert!(effective.credential_attached);
    assert!(tree.validate_all().is_empty());
}

#[test]
fn a_folder_credential_resolves_as_an_inherited_username() {
    let mut tree = Tree::new();
    let mut datacentre = folder("Datacentre");
    let folder_id = datacentre.id;
    let credential = shared("svc-deploy", "svc-deploy");
    let credential_id = credential.id;
    point_at(&mut datacentre, credential_id);
    tree.insert(datacentre).unwrap();
    tree.insert(credential.under(folder_id, 0)).unwrap();

    let conn = connection("web-01").under(folder_id, 1);
    let conn_id = conn.id;
    tree.insert(conn).unwrap();

    let effective = tree.effective_connection(conn_id).unwrap();
    assert_eq!(effective.username.value.as_deref(), Some("svc-deploy"));
    assert_eq!(
        effective.username.provenance,
        Provenance::Ancestor(folder_id)
    );
    assert!(!effective.credential_attached);
}

#[test]
fn a_connection_with_no_credential_anywhere_resolves_no_username() {
    let mut tree = Tree::new();
    let conn = connection("web-01");
    let conn_id = conn.id;
    tree.insert(conn).unwrap();

    let effective = tree.effective_connection(conn_id).unwrap();
    assert_eq!(effective.username.value, None);
    assert!(!effective.credential_attached);
}

// --- deletion ------------------------------------------------------------

#[test]
fn deleting_a_connection_deletes_the_credential_it_owns() {
    let mut tree = Tree::new();
    let mut conn = connection("web-01");
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada");
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    let patch = tree.soft_delete(conn_id, NOW + 1).unwrap();
    assert!(patch.tombstoned.contains(&conn_id));
    assert!(
        patch.tombstoned.contains(&credential_id),
        "the credential the connection owned goes with it: leaving it would \
         leave the user's password in the vault owned by nothing"
    );
    assert!(tree.get(credential_id).is_some_and(Node::is_deleted));
}

#[test]
fn deleting_a_connection_leaves_a_shared_credential_alone() {
    let mut tree = Tree::new();
    let credential = shared("svc-deploy", "svc-deploy");
    let credential_id = credential.id;
    tree.insert(credential).unwrap();

    let mut first = connection("web-01");
    let first_id = first.id;
    point_at(&mut first, credential_id);
    tree.insert(first).unwrap();

    let mut second = connection("web-02");
    let second_id = second.id;
    point_at(&mut second, credential_id);
    tree.insert(second).unwrap();

    tree.soft_delete(first_id, NOW + 1).unwrap();
    assert!(
        tree.get(credential_id)
            .is_some_and(|node| !node.is_deleted())
    );
    // And the connection that still uses it still resolves it.
    let effective = tree.effective_connection(second_id).unwrap();
    assert_eq!(effective.username.value.as_deref(), Some("svc-deploy"));
}

#[test]
fn deleting_a_folder_deletes_the_credentials_owned_by_the_connections_in_it() {
    let mut tree = Tree::new();
    let datacentre = folder("Datacentre");
    let folder_id = datacentre.id;
    tree.insert(datacentre).unwrap();

    let mut conn = connection("web-01").under(folder_id, 0);
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada").under(folder_id, 1);
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    let patch = tree.soft_delete(folder_id, NOW + 1).unwrap();
    assert!(patch.tombstoned.contains(&credential_id));
}

// --- movement ------------------------------------------------------------

#[test]
fn moving_a_connection_moves_the_credential_it_owns() {
    let mut tree = Tree::new();
    let first = folder("Datacentre");
    let first_id = first.id;
    let second = folder("Customer sites");
    let second_id = second.id;
    tree.insert(first).unwrap();
    tree.insert(second).unwrap();

    let mut conn = connection("web-01").under(first_id, 0);
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada").under(first_id, 1);
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    let preview = tree.preview_move(conn_id, Some(second_id)).unwrap();
    assert!(preview.updated.contains(&credential_id));

    let patch = tree.move_node(conn_id, Some(second_id), 0).unwrap();
    assert!(patch.updated.contains(&credential_id));
    assert_eq!(
        tree.get(credential_id).and_then(|node| node.parent_id),
        Some(second_id),
        "a credential left behind in the old folder would be one drag from \
         being deleted with a folder it no longer belongs to"
    );
    assert!(tree.children(Some(second_id)).contains(&credential_id));
    assert!(!tree.children(Some(first_id)).contains(&credential_id));
    assert!(tree.validate_all().is_empty());
}

// --- referential integrity -----------------------------------------------

#[test]
fn a_second_connection_may_not_point_at_a_credential_that_belongs_to_another() {
    let mut tree = Tree::new();
    let mut owner = connection("web-01");
    let owner_id = owner.id;
    let credential = attached(owner_id, "web-01", "ada");
    let credential_id = credential.id;
    point_at(&mut owner, credential_id);
    tree.insert(owner).unwrap();
    tree.insert(credential).unwrap();

    let mut interloper = connection("web-02");
    let interloper_id = interloper.id;
    point_at(&mut interloper, credential_id);
    tree.insert(interloper).unwrap();

    assert_eq!(
        tree.validate_references(interloper_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialAttachedElsewhere {
            credential: credential_id,
            connection: owner_id,
        })
    );
    // The owner is still perfectly valid: it is its own credential.
    assert!(tree.validate_references(owner_id).is_ok());
}

#[test]
fn a_folder_may_not_hand_an_attached_credential_down_to_its_subtree() {
    let mut tree = Tree::new();
    let mut conn = connection("web-01");
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada");
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);

    let mut datacentre = folder("Datacentre");
    let folder_id = datacentre.id;
    point_at(&mut datacentre, credential_id);
    tree.insert(datacentre).unwrap();
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    assert_eq!(
        tree.validate_references(folder_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialAttachedElsewhere {
            credential: credential_id,
            connection: conn_id,
        })
    );
}

#[test]
fn a_credential_attached_to_something_that_is_not_a_connection_is_rejected() {
    let mut tree = Tree::new();
    let datacentre = folder("Datacentre");
    let folder_id = datacentre.id;
    tree.insert(datacentre).unwrap();

    let credential = attached(folder_id, "Datacentre", "ada");
    let credential_id = credential.id;
    tree.insert(credential).unwrap();

    assert_eq!(
        tree.validate_references(credential_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialAttachmentNotAConnection {
            credential: credential_id,
            connection: folder_id,
        })
    );
}

#[test]
fn a_credential_attached_to_a_node_that_is_not_there_is_rejected() {
    let mut tree = Tree::new();
    let missing = NodeId::new();
    let credential = attached(missing, "web-01", "ada");
    let credential_id = credential.id;
    tree.insert(credential).unwrap();

    assert_eq!(
        tree.validate_references(credential_id).unwrap_err(),
        CoreError::Validation(ValidationError::CredentialAttachmentUnknown {
            credential: credential_id,
            connection: missing,
        })
    );
}

#[test]
fn the_tree_reports_which_credentials_a_connection_owns() {
    let mut tree = Tree::new();
    let mut conn = connection("web-01");
    let conn_id = conn.id;
    let credential = attached(conn_id, "web-01", "ada");
    let credential_id = credential.id;
    point_at(&mut conn, credential_id);
    tree.insert(conn).unwrap();
    tree.insert(credential).unwrap();

    let other = shared("svc-deploy", "svc-deploy");
    let other_id = other.id;
    tree.insert(other).unwrap();

    assert_eq!(tree.attached_credentials(conn_id), vec![credential_id]);
    assert!(tree.attached_credentials(other_id).is_empty());
}
