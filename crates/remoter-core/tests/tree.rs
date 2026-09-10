//! Tree structure: indexing, navigation, moves, soft deletes and tombstones.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use remoter_core::{
    ConnectionProps, CoreError, CredentialProps, CredentialRef, GatewayChain, GatewayHop,
    GroupLayout, GroupProps, Inherited, MAX_TREE_DEPTH, Node, NodeId, NodeKind, NodeRef,
    SecretKind, Tree,
};

const NOW: i64 = 1_760_000_000_000;

fn folder(name: &str) -> Node {
    Node::new(NodeKind::folder(), name, NOW)
}

fn connection(name: &str, host: &str) -> Node {
    Node::new(
        NodeKind::Connection(ConnectionProps::new("ssh", host).unwrap()),
        name,
        NOW,
    )
}

fn credential(name: &str) -> Node {
    Node::new(
        NodeKind::Credential(CredentialProps::new(
            name,
            SecretKind::Agent {
                comment_filter: None,
            },
        )),
        name,
        NOW,
    )
}

fn connection_props(node: &mut Node) -> &mut ConnectionProps {
    match &mut node.kind {
        NodeKind::Connection(props) => props,
        _ => panic!("not a connection"),
    }
}

/// Every node's path to the root terminates and repeats nothing.
fn assert_acyclic(tree: &Tree) {
    let ids: Vec<NodeId> = tree.nodes().map(|node| node.id).collect();
    for id in ids {
        let path = tree.path_to_root(id).expect("path must resolve");
        let unique: HashSet<NodeId> = path.iter().copied().collect();
        assert_eq!(unique.len(), path.len(), "path repeats a node: {path:?}");
    }
}

// --- construction and indexing -------------------------------------------

#[test]
fn a_new_tree_is_empty() {
    let tree = Tree::new();
    assert!(tree.is_empty());
    assert_eq!(tree.len(), 0);
    assert!(tree.roots().is_empty());
}

#[test]
fn children_come_back_in_sort_order() {
    let mut tree = Tree::new();
    let root = folder("Datacentre EU-West");
    let root_id = root.id;
    tree.insert(root).unwrap();

    let third = connection("web-03", "web-03.example").under(root_id, 30);
    let first = connection("web-01", "web-01.example").under(root_id, 10);
    let second = connection("web-02", "web-02.example").under(root_id, 20);
    let (a, b, c) = (first.id, second.id, third.id);

    tree.insert(third).unwrap();
    tree.insert(first).unwrap();
    tree.insert(second).unwrap();

    assert_eq!(tree.children(Some(root_id)), &[a, b, c]);
    assert_eq!(tree.roots(), &[root_id]);
}

#[test]
fn inserting_a_duplicate_id_is_rejected() {
    let mut tree = Tree::new();
    let node = folder("Datacentre");
    let id = node.id;
    tree.insert(node).unwrap();
    assert_eq!(
        tree.insert(Node::with_id(id, NodeKind::folder(), "Other", NOW))
            .unwrap_err(),
        CoreError::DuplicateNodeId(id)
    );
}

#[test]
fn inserting_under_a_missing_parent_is_rejected() {
    let mut tree = Tree::new();
    let missing = NodeId::new();
    assert_eq!(
        tree.insert(folder("Web tier").under(missing, 0))
            .unwrap_err(),
        CoreError::ParentNotFound(missing)
    );
}

#[test]
fn only_folders_hold_children() {
    let mut tree = Tree::new();
    let leaf = connection("jump", "jump.acme.io");
    let leaf_id = leaf.id;
    tree.insert(leaf).unwrap();
    assert_eq!(
        tree.insert(folder("nested").under(leaf_id, 0)).unwrap_err(),
        CoreError::NotAContainer(leaf_id)
    );
}

#[test]
fn from_nodes_accepts_any_order_and_rebuilds_the_index() {
    let root = folder("Datacentre");
    let mid = folder("Web tier").under(root.id, 0);
    let leaf = connection("web-01", "web-01.example").under(mid.id, 0);
    let (root_id, mid_id, leaf_id) = (root.id, mid.id, leaf.id);

    let tree = Tree::from_nodes(vec![leaf, root, mid]).unwrap();
    assert_eq!(tree.len(), 3);
    assert_eq!(tree.roots(), &[root_id]);
    assert_eq!(tree.children(Some(root_id)), &[mid_id]);
    assert_eq!(tree.children(Some(mid_id)), &[leaf_id]);
    assert_eq!(tree.depth(leaf_id).unwrap(), 3);
}

#[test]
fn from_nodes_rejects_a_parent_cycle() {
    // Two nodes pointing at each other: unreachable through the mutating API,
    // reachable through a corrupted or hostile store.
    let a_id = NodeId::new();
    let b_id = NodeId::new();
    let mut a = Node::with_id(a_id, NodeKind::folder(), "A", NOW);
    let mut b = Node::with_id(b_id, NodeKind::folder(), "B", NOW);
    a.parent_id = Some(b_id);
    b.parent_id = Some(a_id);

    assert_eq!(
        Tree::from_nodes(vec![a, b]).unwrap_err(),
        CoreError::CorruptTree
    );
}

// --- navigation ----------------------------------------------------------

#[test]
fn ancestors_run_nearest_to_root() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let mid = folder("Web tier").under(root.id, 0);
    let leaf = connection("web-01", "web-01.example").under(mid.id, 0);
    let (root_id, mid_id, leaf_id) = (root.id, mid.id, leaf.id);
    tree.insert(root).unwrap();
    tree.insert(mid).unwrap();
    tree.insert(leaf).unwrap();

    let ancestors: Vec<NodeId> = tree
        .ancestors(leaf_id)
        .unwrap()
        .iter()
        .map(|n| n.id)
        .collect();
    assert_eq!(ancestors, vec![mid_id, root_id]);
    assert_eq!(
        tree.path_to_root(leaf_id).unwrap(),
        vec![leaf_id, mid_id, root_id]
    );
    assert_eq!(tree.depth(root_id).unwrap(), 1);
    assert_eq!(tree.depth(leaf_id).unwrap(), 3);
}

#[test]
fn a_node_is_not_its_own_ancestor() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let mid = folder("Web tier").under(root.id, 0);
    let leaf = connection("web-01", "web-01.example").under(mid.id, 0);
    let (root_id, mid_id, leaf_id) = (root.id, mid.id, leaf.id);
    tree.insert(root).unwrap();
    tree.insert(mid).unwrap();
    tree.insert(leaf).unwrap();

    for id in [root_id, mid_id, leaf_id] {
        assert!(
            !tree.is_ancestor_of(id, id).unwrap(),
            "{id} reported as its own ancestor"
        );
        assert!(!tree.ancestors(id).unwrap().iter().any(|n| n.id == id));
        assert!(!tree.descendants(id).unwrap().contains(&id));
    }

    assert!(tree.is_ancestor_of(root_id, leaf_id).unwrap());
    assert!(!tree.is_ancestor_of(leaf_id, root_id).unwrap());
}

#[test]
fn descendants_come_back_in_pre_order() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let web = folder("Web tier").under(root.id, 0);
    let db = folder("Database tier").under(root.id, 1);
    let web1 = connection("web-01", "web-01.example").under(web.id, 0);
    let web2 = connection("web-02", "web-02.example").under(web.id, 1);
    let db1 = connection("db-primary", "db-primary").under(db.id, 0);
    let (root_id, web_id, db_id, web1_id, web2_id, db1_id) =
        (root.id, web.id, db.id, web1.id, web2.id, db1.id);
    for node in [root, web, db, web1, web2, db1] {
        tree.insert(node).unwrap();
    }

    assert_eq!(
        tree.descendants(root_id).unwrap(),
        vec![web_id, web1_id, web2_id, db_id, db1_id]
    );
    assert_eq!(
        tree.subtree(root_id).unwrap(),
        vec![root_id, web_id, web1_id, web2_id, db_id, db1_id]
    );
}

// --- moves ---------------------------------------------------------------

#[test]
fn a_move_touches_exactly_one_row() {
    let mut tree = Tree::new();
    let source = folder("Customer sites");
    let target = folder("Datacentre");
    let moved = folder("Contoso").under(source.id, 0);
    let (source_id, target_id, moved_id) = (source.id, target.id, moved.id);
    tree.insert(source).unwrap();
    tree.insert(target).unwrap();
    tree.insert(moved).unwrap();

    // Twenty descendants, all of which change their effective values and none
    // of which change a row.
    let mut descendants = Vec::new();
    for index in 0..20 {
        let child = connection(&format!("host-{index}"), "ctso-dc01").under(moved_id, index);
        descendants.push(child.id);
        tree.insert(child).unwrap();
    }

    let patch = tree.move_node(moved_id, Some(target_id), 0).unwrap();
    assert_eq!(patch.rows_touched(), 1);
    assert_eq!(patch.updated, vec![moved_id]);
    assert_eq!(patch.resolution_changed.len(), 21);
    assert_eq!(patch.resolution_changed[0], moved_id);

    assert_eq!(tree.children(Some(target_id)), &[moved_id]);
    assert!(tree.children(Some(source_id)).is_empty());
    assert_eq!(tree.get(moved_id).unwrap().parent_id, Some(target_id));
    assert_acyclic(&tree);
}

#[test]
fn preview_move_reports_the_same_patch_without_moving() {
    let mut tree = Tree::new();
    let source = folder("Customer sites");
    let target = folder("Datacentre");
    let moved = folder("Contoso").under(source.id, 0);
    let (source_id, target_id, moved_id) = (source.id, target.id, moved.id);
    tree.insert(source).unwrap();
    tree.insert(target).unwrap();
    tree.insert(moved).unwrap();

    let preview = tree.preview_move(moved_id, Some(target_id)).unwrap();
    assert_eq!(tree.get(moved_id).unwrap().parent_id, Some(source_id));

    let applied = tree.move_node(moved_id, Some(target_id), 0).unwrap();
    assert_eq!(preview, applied);
}

#[test]
fn a_node_cannot_be_moved_under_itself() {
    let mut tree = Tree::new();
    let node = folder("Datacentre");
    let id = node.id;
    tree.insert(node).unwrap();

    assert_eq!(
        tree.move_node(id, Some(id), 0).unwrap_err(),
        CoreError::Cycle {
            node: id,
            parent: id
        }
    );
    assert_acyclic(&tree);
}

#[test]
fn a_node_cannot_be_moved_under_its_own_descendant() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let mid = folder("Web tier").under(root.id, 0);
    let deep = folder("Canary").under(mid.id, 0);
    let (root_id, mid_id, deep_id) = (root.id, mid.id, deep.id);
    tree.insert(root).unwrap();
    tree.insert(mid).unwrap();
    tree.insert(deep).unwrap();

    for parent in [mid_id, deep_id] {
        assert_eq!(
            tree.move_node(root_id, Some(parent), 0).unwrap_err(),
            CoreError::Cycle {
                node: root_id,
                parent
            }
        );
    }
    // The rejected move left nothing half-applied.
    assert_eq!(tree.get(root_id).unwrap().parent_id, None);
    assert_eq!(tree.children(Some(root_id)), &[mid_id]);
    assert_acyclic(&tree);
}

#[test]
fn a_move_to_the_root_is_allowed() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let child = folder("Web tier").under(root.id, 0);
    let (root_id, child_id) = (root.id, child.id);
    tree.insert(root).unwrap();
    tree.insert(child).unwrap();

    tree.move_node(child_id, None, 5).unwrap();
    assert_eq!(tree.get(child_id).unwrap().parent_id, None);
    assert_eq!(tree.get(child_id).unwrap().sort_order, 5);
    assert!(tree.roots().contains(&child_id));
    assert!(tree.children(Some(root_id)).is_empty());
}

#[test]
fn a_move_bumps_the_revision() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let child = folder("Web tier").under(root.id, 0);
    let child_id = child.id;
    tree.insert(root).unwrap();
    tree.insert(child).unwrap();

    let before = tree.get(child_id).unwrap().revision;
    tree.move_node(child_id, None, 0).unwrap();
    assert_eq!(tree.get(child_id).unwrap().revision, before + 1);
}

// --- depth ---------------------------------------------------------------

#[test]
fn a_chain_at_the_depth_limit_is_accepted_and_one_deeper_is_not() {
    let mut tree = Tree::new();
    let mut parent: Option<NodeId> = None;
    let mut ids = Vec::new();
    for level in 0..MAX_TREE_DEPTH {
        let mut node = folder(&format!("level-{level}"));
        node.parent_id = parent;
        let id = node.id;
        tree.insert(node).unwrap();
        ids.push(id);
        parent = Some(id);
    }
    assert_eq!(tree.depth(ids[MAX_TREE_DEPTH - 1]).unwrap(), MAX_TREE_DEPTH);

    let mut over = folder("one-too-deep");
    over.parent_id = parent;
    assert_eq!(
        tree.insert(over).unwrap_err(),
        CoreError::DepthExceeded {
            depth: MAX_TREE_DEPTH + 1
        }
    );
}

#[test]
fn a_move_that_would_exceed_the_depth_limit_is_rejected() {
    let mut tree = Tree::new();

    // A chain occupying all but two levels.
    let mut parent: Option<NodeId> = None;
    for level in 0..(MAX_TREE_DEPTH - 2) {
        let mut node = folder(&format!("level-{level}"));
        node.parent_id = parent;
        let id = node.id;
        tree.insert(node).unwrap();
        parent = Some(id);
    }
    let deepest = parent.unwrap();

    // A separate three-level subtree does not fit under it.
    let a = folder("a");
    let b = folder("b").under(a.id, 0);
    let c = folder("c").under(b.id, 0);
    let a_id = a.id;
    tree.insert(a).unwrap();
    tree.insert(b).unwrap();
    tree.insert(c).unwrap();

    assert_eq!(
        tree.move_node(a_id, Some(deepest), 0).unwrap_err(),
        CoreError::DepthExceeded {
            depth: MAX_TREE_DEPTH + 1
        }
    );

    // A two-level one does.
    let d = folder("d");
    let e = folder("e").under(d.id, 0);
    let d_id = d.id;
    tree.insert(d).unwrap();
    tree.insert(e).unwrap();
    assert!(tree.move_node(d_id, Some(deepest), 0).is_ok());
}

// --- update --------------------------------------------------------------

#[test]
fn update_bumps_the_revision_and_preserves_creation_time() {
    let mut tree = Tree::new();
    let node = folder("Datacentre");
    let id = node.id;
    tree.insert(node).unwrap();

    let mut edited = tree.get(id).unwrap().clone();
    edited.name = "Datacentre EU-West".to_owned();
    edited.created_at = 0;
    edited.revision = 99;
    edited.updated_at = NOW + 1_000;
    tree.update(edited).unwrap();

    let stored = tree.get(id).unwrap();
    assert_eq!(stored.name, "Datacentre EU-West");
    assert_eq!(stored.revision, 2);
    assert_eq!(stored.created_at, NOW);
    assert_eq!(stored.updated_at, NOW + 1_000);
}

#[test]
fn update_refuses_to_re_parent() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let other = folder("Customer sites");
    let child = folder("Web tier").under(root.id, 0);
    let (other_id, child_id) = (other.id, child.id);
    tree.insert(root).unwrap();
    tree.insert(other).unwrap();
    tree.insert(child).unwrap();

    let mut edited = tree.get(child_id).unwrap().clone();
    edited.parent_id = Some(other_id);
    assert_eq!(
        tree.update(edited).unwrap_err(),
        CoreError::ParentChanged { node: child_id }
    );
}

#[test]
fn an_edit_that_changes_inheritance_invalidates_the_subtree() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let child = connection("web-01", "web-01.example").under(root.id, 0);
    let (root_id, child_id) = (root.id, child.id);
    tree.insert(root).unwrap();
    tree.insert(child).unwrap();

    // A description edit changes nothing anyone can inherit.
    let mut edited = tree.get(root_id).unwrap().clone();
    edited.description = "EU-West".to_owned();
    let patch = tree.update(edited).unwrap();
    assert_eq!(patch.resolution_changed, vec![root_id]);

    // A port edit changes every descendant's effective value.
    let mut edited = tree.get(root_id).unwrap().clone();
    if let NodeKind::Folder(props) = &mut edited.kind {
        props.port = Inherited::Explicit(2222);
    }
    let patch = tree.update(edited).unwrap();
    assert_eq!(patch.resolution_changed, vec![root_id, child_id]);
}

#[test]
fn update_re_sorts_siblings_when_the_order_changes() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let root_id = root.id;
    tree.insert(root).unwrap();
    let first = connection("web-01", "web-01.example").under(root_id, 10);
    let second = connection("web-02", "web-02.example").under(root_id, 20);
    let (a, b) = (first.id, second.id);
    tree.insert(first).unwrap();
    tree.insert(second).unwrap();
    assert_eq!(tree.children(Some(root_id)), &[a, b]);

    let mut edited = tree.get(a).unwrap().clone();
    edited.sort_order = 30;
    tree.update(edited).unwrap();
    assert_eq!(tree.children(Some(root_id)), &[b, a]);
}

// --- soft delete and tombstones ------------------------------------------

#[test]
fn soft_delete_tombstones_the_whole_subtree() {
    let mut tree = Tree::new();
    let root = folder("Customer sites");
    let mid = folder("Contoso").under(root.id, 0);
    let leaf = connection("ctso-dc01", "ctso-dc01").under(mid.id, 0);
    let (root_id, mid_id, leaf_id) = (root.id, mid.id, leaf.id);
    tree.insert(root).unwrap();
    tree.insert(mid).unwrap();
    tree.insert(leaf).unwrap();

    let patch = tree.soft_delete(mid_id, NOW + 1).unwrap();
    assert_eq!(patch.tombstoned, vec![mid_id, leaf_id]);

    assert!(tree.get(mid_id).unwrap().is_deleted());
    assert!(tree.get(leaf_id).unwrap().is_deleted());
    assert!(!tree.get(root_id).unwrap().is_deleted());
    assert_eq!(tree.get(leaf_id).unwrap().deleted_at, Some(NOW + 1));

    // Structure survives, so the interface can still show what was deleted.
    assert_eq!(tree.children(Some(mid_id)), &[leaf_id]);
}

#[test]
fn deleting_a_credential_turns_references_into_tombstones() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let root_id = root.id;
    tree.insert(root).unwrap();

    let cred = credential("svc-deploy").under(root_id, 0);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    let mut conn = connection("web-01", "web-01.example").under(root_id, 1);
    let conn_id = conn.id;
    connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(cred_id));
    tree.insert(conn).unwrap();

    assert_eq!(tree.referrers(cred_id), vec![conn_id]);

    let patch = tree.soft_delete(cred_id, NOW + 1).unwrap();
    assert_eq!(patch.tombstoned, vec![cred_id]);
    assert_eq!(patch.updated, vec![conn_id]);

    let stored = tree.get(conn_id).unwrap();
    let Some(Inherited::Explicit(reference)) = stored.credential_field() else {
        panic!("credential reference lost");
    };
    assert!(reference.is_deleted());
    assert_eq!(reference.id(), cred_id);
    assert_eq!(
        reference.as_node_ref(),
        &NodeRef::Deleted {
            id: cred_id,
            name: "svc-deploy".to_owned()
        }
    );

    // The connection no longer counts as a live referrer.
    assert!(tree.referrers(cred_id).is_empty());
}

#[test]
fn deleting_a_gateway_host_tombstones_the_hop() {
    let mut tree = Tree::new();
    let jump = connection("jump", "jump.acme.io");
    let jump_id = jump.id;
    tree.insert(jump).unwrap();

    let mut conn = connection("web-01", "web-01.example");
    let conn_id = conn.id;
    connection_props(&mut conn).gateway =
        Inherited::Explicit(vec![GatewayHop::new(jump_id)].into_iter().collect());
    tree.insert(conn).unwrap();

    let patch = tree.soft_delete(jump_id, NOW + 1).unwrap();
    assert_eq!(patch.updated, vec![conn_id]);

    let stored = tree.get(conn_id).unwrap();
    let Some(Inherited::Explicit(chain)) = stored.gateway_field() else {
        panic!("gateway chain lost");
    };
    assert!(chain.hops[0].node.is_deleted());
}

#[test]
fn deleting_a_group_member_tombstones_the_membership() {
    let mut tree = Tree::new();
    let member = connection("web-01", "web-01.example");
    let member_id = member.id;
    tree.insert(member).unwrap();

    let group = Node::new(
        NodeKind::Group(GroupProps {
            members: vec![NodeRef::live(member_id)],
            layout: GroupLayout::Grid { rows: 2, cols: 2 },
            broadcast: false,
        }),
        "Web tier",
        NOW,
    );
    let group_id = group.id;
    tree.insert(group).unwrap();

    let patch = tree.soft_delete(member_id, NOW + 1).unwrap();
    assert_eq!(patch.updated, vec![group_id]);

    let stored = tree.get(group_id).unwrap();
    let members = &stored.kind.as_group().unwrap().members;
    assert!(members[0].is_deleted());
}

#[test]
fn a_second_soft_delete_is_a_no_op() {
    let mut tree = Tree::new();
    let node = folder("Contoso");
    let id = node.id;
    tree.insert(node).unwrap();

    assert_eq!(tree.soft_delete(id, NOW + 1).unwrap().tombstoned, vec![id]);
    let second = tree.soft_delete(id, NOW + 2).unwrap();
    assert!(second.is_empty());
    assert_eq!(tree.get(id).unwrap().deleted_at, Some(NOW + 1));
}

#[test]
fn a_reference_inside_the_deleted_subtree_is_left_alone() {
    // Both ends went away together; rewriting the reference would only add
    // noise to a subtree the user is no longer looking at.
    let mut tree = Tree::new();
    let root = folder("Contoso");
    let root_id = root.id;
    tree.insert(root).unwrap();

    let cred = credential("CONTOSO-admin").under(root_id, 0);
    let cred_id = cred.id;
    tree.insert(cred).unwrap();

    let mut conn = connection("ctso-dc01", "ctso-dc01").under(root_id, 1);
    let conn_id = conn.id;
    connection_props(&mut conn).credential = Inherited::Explicit(CredentialRef::live(cred_id));
    tree.insert(conn).unwrap();

    let patch = tree.soft_delete(root_id, NOW + 1).unwrap();
    assert_eq!(patch.tombstoned, vec![root_id, cred_id, conn_id]);
    assert!(patch.updated.is_empty());

    let Some(Inherited::Explicit(reference)) = tree.get(conn_id).unwrap().credential_field() else {
        panic!("credential reference lost");
    };
    assert!(!reference.is_deleted());
}

// --- error paths ---------------------------------------------------------

#[test]
fn operations_on_a_missing_node_report_it() {
    let mut tree = Tree::new();
    let missing = NodeId::new();
    assert_eq!(tree.get(missing), None);
    assert_eq!(
        tree.ancestors(missing).unwrap_err(),
        CoreError::NodeNotFound(missing)
    );
    assert_eq!(
        tree.descendants(missing).unwrap_err(),
        CoreError::NodeNotFound(missing)
    );
    assert_eq!(
        tree.move_node(missing, None, 0).unwrap_err(),
        CoreError::NodeNotFound(missing)
    );
    assert_eq!(
        tree.soft_delete(missing, NOW).unwrap_err(),
        CoreError::NodeNotFound(missing)
    );
    assert_eq!(
        tree.effective_connection(missing).unwrap_err(),
        CoreError::NodeNotFound(missing)
    );
}

#[test]
fn effective_connection_refuses_a_non_connection() {
    let mut tree = Tree::new();
    let node = folder("Datacentre");
    let id = node.id;
    tree.insert(node).unwrap();
    assert_eq!(
        tree.effective_connection(id).unwrap_err(),
        CoreError::NotAConnection(id)
    );
}

#[test]
fn into_nodes_returns_everything_that_went_in() {
    let mut tree = Tree::new();
    let root = folder("Datacentre");
    let child = connection("web-01", "web-01.example").under(root.id, 0);
    let ids: HashSet<NodeId> = [root.id, child.id].into_iter().collect();
    tree.insert(root).unwrap();
    tree.insert(child).unwrap();

    let out: HashSet<NodeId> = tree.into_nodes().into_iter().map(|node| node.id).collect();
    assert_eq!(out, ids);
}

#[test]
fn an_empty_gateway_chain_is_direct_by_construction() {
    assert!(GatewayChain::default().is_direct());
    assert!(GatewayChain::default().is_empty());
}
