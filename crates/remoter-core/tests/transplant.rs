//! Taking nodes out of one tree and putting them into another: a detached copy
//! that behaves as it did in place, and new identities with every reference
//! among the nodes following them.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use remoter_core::{
    ConnectionProps, CredentialProps, CredentialRef, GatewayChain, GatewayHop, GroupProps,
    Inherited, Node, NodeId, NodeKind, NodeRef, SecretKind, Tree, rekey,
};

const NOW: i64 = 1_760_000_000_000;

fn agent() -> SecretKind {
    SecretKind::Agent {
        comment_filter: None,
    }
}

fn connection(name: &str) -> Node {
    Node::new(
        NodeKind::Connection(ConnectionProps::new("ssh", format!("{name}.example")).unwrap()),
        name,
        NOW,
    )
}

fn props(node: &mut Node) -> &mut ConnectionProps {
    match &mut node.kind {
        NodeKind::Connection(props) => props,
        _ => panic!("not a connection"),
    }
}

fn under(mut node: Node, parent: &Node) -> Node {
    node.parent_id = Some(parent.id);
    node
}

#[test]
fn a_detached_connection_keeps_what_its_folders_gave_it() {
    let svc = Node::new(
        NodeKind::Credential(CredentialProps::new("svc", agent())),
        "svc",
        NOW,
    );
    let bastion = connection("bastion");

    let mut outer = Node::new(NodeKind::folder(), "Estate", NOW);
    let NodeKind::Folder(folder) = &mut outer.kind else {
        unreachable!()
    };
    folder.port = Inherited::Explicit(2222);
    folder.credential = Inherited::Explicit(CredentialRef::live(svc.id));
    folder.settings.insert("ssh.compression", "yes").unwrap();
    folder.settings.insert("ssh.term", "xterm").unwrap();
    outer.colour = Some("#336699".into());

    let mut inner = under(Node::new(NodeKind::folder(), "Web", NOW), &outer);
    let NodeKind::Folder(folder) = &mut inner.kind else {
        unreachable!()
    };
    folder.gateway = Inherited::Default;
    folder.keepalive_secs = Inherited::Explicit(30);
    folder
        .settings
        .insert("ssh.term", "xterm-256color")
        .unwrap();

    let mut web = under(connection("web-01"), &inner);
    props(&mut web).port = Inherited::Explicit(22);
    props(&mut web).gateway = Inherited::Inherit;
    let web_id = web.id;

    let mut tree = Tree::new();
    for node in [svc.clone(), bastion, outer, inner, web] {
        tree.insert(node).unwrap();
    }
    let before = tree.effective_connection(web_id).unwrap();

    let detached = tree.detached(web_id).unwrap();
    assert_eq!(detached.parent_id, None);
    let NodeKind::Connection(connection) = &detached.kind else {
        panic!("still a connection");
    };
    // Its own value stays its own.
    assert_eq!(connection.port, Inherited::Explicit(22));
    // A folder's value becomes its own.
    assert_eq!(
        connection.credential,
        Inherited::Explicit(CredentialRef::live(svc.id))
    );
    assert_eq!(connection.keepalive_secs, Inherited::Explicit(30));
    // A folder's deliberate "none" stays a deliberate none, not an inherit.
    assert_eq!(connection.gateway, Inherited::Default);
    // Nothing above set a timeout: still inherited.
    assert_eq!(connection.connect_timeout_ms, Inherited::Inherit);
    // The nearer folder's setting wins, as resolution has it.
    assert_eq!(connection.settings.get("ssh.term"), Some("xterm-256color"));
    assert_eq!(connection.settings.get("ssh.compression"), Some("yes"));
    assert_eq!(detached.colour.as_deref(), Some("#336699"));

    // And the proof: on its own, it resolves to what it resolved to in place.
    let mut alone = Tree::new();
    alone.insert(svc).unwrap();
    alone.insert(detached).unwrap();
    let after = alone.effective_connection(web_id).unwrap();
    assert_eq!(after.port.value, before.port.value);
    assert_eq!(after.credential.value, before.credential.value);
    assert_eq!(after.gateway.value, before.gateway.value);
    assert_eq!(after.keepalive_secs.value, before.keepalive_secs.value);
    assert_eq!(
        after
            .settings
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect::<Vec<_>>(),
        before
            .settings
            .iter()
            .map(|(k, v)| (k.clone(), v.value.clone()))
            .collect::<Vec<_>>()
    );
}

#[test]
fn rekeying_moves_every_reference_among_the_nodes_and_none_outside_them() {
    let outside = NodeId::new();
    let mut folder = Node::new(NodeKind::folder(), "Estate", NOW);
    let mut credential = Node::new(
        NodeKind::Credential(CredentialProps::new("root", agent())),
        "root",
        NOW,
    );
    let mut bastion = connection("bastion");
    let mut web = connection("web");
    let mut group = Node::new(NodeKind::Group(GroupProps::default()), "All", NOW);

    bastion.parent_id = Some(folder.id);
    web.parent_id = Some(folder.id);
    credential.parent_id = Some(folder.id);
    let NodeKind::Credential(owned) = &mut credential.kind else {
        unreachable!()
    };
    owned.attached_to = Some(web.id);
    props(&mut web).credential = Inherited::Explicit(CredentialRef::live(credential.id));
    props(&mut web).gateway = Inherited::Explicit(GatewayChain {
        hops: vec![
            GatewayHop::with_credential(bastion.id, CredentialRef::live(credential.id)),
            GatewayHop::new(outside),
        ],
    });
    let NodeKind::Folder(props_folder) = &mut folder.kind else {
        unreachable!()
    };
    props_folder.credential = Inherited::Explicit(CredentialRef::deleted(credential.id, "old"));
    let NodeKind::Group(members) = &mut group.kind else {
        unreachable!()
    };
    members.members = vec![NodeRef::live(web.id), NodeRef::live(outside)];

    let old = [folder.id, credential.id, bastion.id, web.id, group.id];
    let mut nodes = vec![folder, credential, bastion, web, group];
    let map = rekey(&mut nodes);

    assert_eq!(map.len(), 5);
    for (node, old_id) in nodes.iter().zip(old) {
        assert_ne!(node.id, old_id, "{} kept its id", node.name);
        assert_eq!(map.get(&old_id), Some(&node.id));
    }
    let [folder, credential, bastion, web, group] = &nodes[..] else {
        unreachable!()
    };
    assert_eq!(bastion.parent_id, Some(folder.id));
    assert_eq!(credential.parent_id, Some(folder.id));
    assert_eq!(
        credential.kind.as_credential().unwrap().attached_to,
        Some(web.id)
    );

    let web_props = web.kind.as_connection().unwrap();
    assert_eq!(
        web_props.credential,
        Inherited::Explicit(CredentialRef::live(credential.id))
    );
    let Inherited::Explicit(chain) = &web_props.gateway else {
        panic!("the chain went");
    };
    assert_eq!(chain.hops[0].node, NodeRef::live(bastion.id));
    assert_eq!(
        chain.hops[0].credential,
        Some(CredentialRef::live(credential.id))
    );
    // A hop outside the set is left for the caller.
    assert_eq!(chain.hops[1].node, NodeRef::live(outside));

    // A tombstone follows too, and keeps its name.
    assert_eq!(
        folder.kind.as_folder().unwrap().credential,
        Inherited::Explicit(CredentialRef::deleted(credential.id, "old"))
    );
    assert_eq!(
        group.kind.as_group().unwrap().members,
        vec![NodeRef::live(web.id), NodeRef::live(outside)]
    );
    // A root stays a root.
    assert_eq!(folder.parent_id, None);
}

#[test]
fn the_references_a_node_holds_are_all_listed() {
    let hop = NodeId::new();
    let hop_credential = NodeId::new();
    let own = NodeId::new();
    let mut web = connection("web");
    props(&mut web).credential = Inherited::Explicit(CredentialRef::live(own));
    props(&mut web).gateway = Inherited::Explicit(GatewayChain {
        hops: vec![GatewayHop::with_credential(
            hop,
            CredentialRef::live(hop_credential),
        )],
    });
    let ids: Vec<NodeId> = web.references().iter().map(|r| r.id()).collect();
    assert_eq!(ids, [own, hop, hop_credential]);

    // Inherit is not a reference.
    assert!(connection("plain").references().is_empty());
}
