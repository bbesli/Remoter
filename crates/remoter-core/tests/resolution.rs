//! Inheritance resolution and the flattened connection it produces.
//!
//! The tree used throughout is the one from the data model document:
//!
//! ```text
//! Datacentre EU-West        port 2222, credential svc-deploy, terminal xterm
//! └─ Web tier               port 22 (override)
//!    └─ web-01              everything inherited
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use remoter_core::{
    ConnectionProps, CredentialProps, CredentialRef, FolderProps, Inherited, Node, NodeId,
    NodeKind, Provenance, RecordingPolicy, SecretKind, Tree,
};

const NOW: i64 = 1_760_000_000_000;

struct Fixture {
    tree: Tree,
    datacentre: NodeId,
    web_tier: NodeId,
    web01: NodeId,
    credential: NodeId,
}

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

fn folder_props(node: &mut Node) -> &mut FolderProps {
    match &mut node.kind {
        NodeKind::Folder(props) => props,
        _ => panic!("not a folder"),
    }
}

fn connection_props(node: &mut Node) -> &mut ConnectionProps {
    match &mut node.kind {
        NodeKind::Connection(props) => props,
        _ => panic!("not a connection"),
    }
}

fn fixture() -> Fixture {
    let mut tree = Tree::new();

    let mut datacentre = folder("Datacentre EU-West");
    let datacentre_id = datacentre.id;

    let credential_node = Node::new(
        NodeKind::Credential(CredentialProps::new(
            "svc-deploy",
            SecretKind::Agent {
                comment_filter: None,
            },
        )),
        "svc-deploy",
        NOW,
    )
    .under(datacentre_id, 100);
    let credential_id = credential_node.id;

    datacentre.icon = Some("lucide:building".to_owned());
    datacentre.colour = Some("#0055aa".to_owned());
    {
        let props = folder_props(&mut datacentre);
        props.port = Inherited::Explicit(2222);
        props.credential = Inherited::Explicit(CredentialRef::live(credential_id));
        props.recording = Inherited::Explicit(RecordingPolicy::Always);
        props.settings.insert("terminal.type", "xterm").unwrap();
        props.settings.insert("terminal.bell", "off").unwrap();
    }

    let mut web_tier = folder("Web tier").under(datacentre_id, 0);
    let web_tier_id = web_tier.id;
    folder_props(&mut web_tier).port = Inherited::Explicit(22);
    folder_props(&mut web_tier)
        .settings
        .insert("terminal.type", "xterm-256color")
        .unwrap();

    let web01 = connection("web-01", "web-01.eu.acme.internal").under(web_tier_id, 0);
    let web01_id = web01.id;

    tree.insert(datacentre).unwrap();
    tree.insert(credential_node).unwrap();
    tree.insert(web_tier).unwrap();
    tree.insert(web01).unwrap();

    Fixture {
        tree,
        datacentre: datacentre_id,
        web_tier: web_tier_id,
        web01: web01_id,
        credential: credential_id,
    }
}

// --- the three states ----------------------------------------------------

#[test]
fn an_explicit_value_on_the_node_wins() {
    let mut f = fixture();
    let mut edited = f.tree.get(f.web01).unwrap().clone();
    connection_props(&mut edited).port = Inherited::Explicit(2200);
    f.tree.update(edited).unwrap();

    let port = f.tree.resolve(f.web01, Node::port_field).unwrap();
    assert_eq!(port.value, 2200);
    assert_eq!(port.provenance, Provenance::Own(f.web01));
    assert!(!port.is_inherited());
    assert!(!port.is_default());
}

#[test]
fn the_nearest_explicit_ancestor_wins() {
    let f = fixture();
    let port = f.tree.resolve(f.web01, Node::port_field).unwrap();
    assert_eq!(port.value, 22);
    assert_eq!(port.provenance, Provenance::Ancestor(f.web_tier));
    assert_eq!(port.source(), Some(f.web_tier));
    assert!(port.is_inherited());
}

#[test]
fn default_stops_the_walk_at_the_node_that_declared_it() {
    let mut f = fixture();
    let mut edited = f.tree.get(f.web_tier).unwrap().clone();
    folder_props(&mut edited).port = Inherited::Default;
    f.tree.update(edited).unwrap();

    // The grandparent's explicit 2222 is not reached: `Default` is a stop, not
    // a pass-through.
    let port = f.tree.resolve_optional(f.web01, Node::port_field).unwrap();
    assert_eq!(port.value, None);
    assert_eq!(port.provenance, Provenance::DefaultAt(f.web_tier));
    assert!(port.is_default());
    assert!(!port.is_inherited());
}

#[test]
fn a_walk_that_reaches_the_root_reports_the_root_default() {
    let mut f = fixture();
    for id in [f.datacentre, f.web_tier] {
        let mut edited = f.tree.get(id).unwrap().clone();
        folder_props(&mut edited).port = Inherited::Inherit;
        f.tree.update(edited).unwrap();
    }

    let port = f.tree.resolve_optional(f.web01, Node::port_field).unwrap();
    assert_eq!(port.value, None);
    assert_eq!(port.provenance, Provenance::DefaultAtRoot);
    assert_eq!(port.source(), None);
}

#[test]
fn a_kind_without_the_field_is_transparent_to_the_walk() {
    // A credential carries no port, so resolving one on it inherits the
    // folder's rather than pretending the field is set to something.
    let f = fixture();
    let port = f.tree.resolve(f.credential, Node::port_field).unwrap();
    assert_eq!(port.value, 2222);
    assert_eq!(port.provenance, Provenance::Ancestor(f.datacentre));
}

#[test]
fn a_root_node_resolves_its_own_explicit_value() {
    let f = fixture();
    let port = f.tree.resolve(f.datacentre, Node::port_field).unwrap();
    assert_eq!(port.value, 2222);
    assert_eq!(port.provenance, Provenance::Own(f.datacentre));
}

// --- the flattened connection --------------------------------------------

#[test]
fn an_effective_connection_carries_a_provenance_per_field() {
    let f = fixture();
    let effective = f.tree.effective_connection(f.web01).unwrap();

    assert_eq!(effective.node, f.web01);
    assert_eq!(effective.name, "web-01");
    assert_eq!(effective.protocol.as_str(), "ssh");
    assert_eq!(effective.host, "web-01.eu.acme.internal");

    assert_eq!(effective.port.value, Some(22));
    assert_eq!(effective.port.provenance, Provenance::Ancestor(f.web_tier));

    assert_eq!(
        effective.credential.value.as_ref().map(CredentialRef::id),
        Some(f.credential)
    );
    assert_eq!(
        effective.credential.provenance,
        Provenance::Ancestor(f.datacentre)
    );

    assert_eq!(effective.recording.value, RecordingPolicy::Always);
    assert_eq!(
        effective.recording.provenance,
        Provenance::Ancestor(f.datacentre)
    );

    // Nothing on the path sets these, so they land on the type default.
    assert!(effective.gateway.value.is_direct());
    assert_eq!(effective.gateway.provenance, Provenance::DefaultAtRoot);
    assert_eq!(effective.connect_timeout_ms.value, None);
    assert!(effective.on_connect.value.is_empty());

    // Presentation resolves by nearest node that sets it.
    assert_eq!(effective.icon.value.as_deref(), Some("lucide:building"));
    assert_eq!(
        effective.icon.provenance,
        Provenance::Ancestor(f.datacentre)
    );
    assert_eq!(effective.colour.value.as_deref(), Some("#0055aa"));

    let provenance = effective.provenance();
    assert_eq!(provenance.len(), 13);
    assert!(provenance.iter().any(|(field, _)| *field == "port"));
    // The username resolves with the credential that holds it.
    assert!(provenance.iter().any(|(field, _)| *field == "username"));
    assert!(effective.has_inherited_fields());
}

#[test]
fn settings_merge_per_key_with_the_nearest_node_winning() {
    let mut f = fixture();
    let mut edited = f.tree.get(f.web01).unwrap().clone();
    connection_props(&mut edited)
        .settings
        .insert("colour.depth", "32")
        .unwrap();
    f.tree.update(edited).unwrap();

    let effective = f.tree.effective_connection(f.web01).unwrap();

    // Overridden by the nearer folder.
    let terminal = &effective.settings["terminal.type"];
    assert_eq!(terminal.value, "xterm-256color");
    assert_eq!(terminal.provenance, Provenance::Ancestor(f.web_tier));

    // Not overridden, so it survives from the far folder.
    let bell = &effective.settings["terminal.bell"];
    assert_eq!(bell.value, "off");
    assert_eq!(bell.provenance, Provenance::Ancestor(f.datacentre));

    // Set on the connection itself.
    let depth = &effective.settings["colour.depth"];
    assert_eq!(depth.value, "32");
    assert_eq!(depth.provenance, Provenance::Own(f.web01));
}

#[test]
fn a_port_falls_back_to_the_protocol_default() {
    let mut f = fixture();
    for id in [f.datacentre, f.web_tier] {
        let mut edited = f.tree.get(id).unwrap().clone();
        folder_props(&mut edited).port = Inherited::Inherit;
        f.tree.update(edited).unwrap();
    }

    let effective = f.tree.effective_connection(f.web01).unwrap();
    assert_eq!(effective.port.value, Some(22));
    assert_eq!(effective.port.provenance, Provenance::DefaultAtRoot);
}

#[test]
fn an_unknown_protocol_gets_no_port_default() {
    let mut tree = Tree::new();
    let node = Node::new(
        NodeKind::Connection(ConnectionProps::new("vendor.x", "appliance.example").unwrap()),
        "appliance",
        NOW,
    );
    let id = node.id;
    tree.insert(node).unwrap();

    let effective = tree.effective_connection(id).unwrap();
    assert_eq!(effective.port.value, None);
    assert!(!effective.has_inherited_fields());
}

#[test]
fn moving_a_node_changes_what_it_resolves_to() {
    let mut f = fixture();
    // Straight off the shared folder onto the root: the port override and the
    // credential both stop applying.
    assert_eq!(f.tree.resolve(f.web01, Node::port_field).unwrap().value, 22);

    f.tree.move_node(f.web01, None, 0).unwrap();

    let effective = f.tree.effective_connection(f.web01).unwrap();
    assert_eq!(effective.port.value, Some(22)); // now the ssh default
    assert_eq!(effective.port.provenance, Provenance::DefaultAtRoot);
    assert!(effective.credential.value.is_none());
    assert!(effective.settings.is_empty());
}

// --- inherited helpers ---------------------------------------------------

#[test]
fn inherited_defaults_to_inherit() {
    let field: Inherited<u16> = Inherited::default();
    assert!(field.is_inherit());
    assert!(!field.is_explicit());
    assert!(!field.is_default());
    assert_eq!(field.explicit(), None);

    let field = Inherited::Explicit(22u16);
    assert_eq!(field.explicit(), Some(&22));
    assert_eq!(field.map(u32::from), Inherited::Explicit(22u32));
}

#[test]
fn provenance_distinguishes_own_from_inherited_from_default() {
    let id = NodeId::new();
    assert!(!Provenance::Own(id).is_inherited());
    assert!(Provenance::Ancestor(id).is_inherited());
    assert!(Provenance::DefaultAt(id).is_default());
    assert!(Provenance::DefaultAtRoot.is_default());
    assert_eq!(Provenance::DefaultAtRoot.source(), None);
    assert_eq!(Provenance::DefaultAt(id).source(), Some(id));
}
