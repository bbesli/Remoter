//! Property tests for inheritance resolution.
//!
//! The resolver is a pure function of a node and its ancestors, which is the
//! whole reason the domain model is shaped the way it is. That makes the two
//! properties that matter cheap to state over arbitrary trees: whatever comes
//! back was put there by someone on the path, and asking twice gives the same
//! answer.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use remoter_core::{
    ConnectionProps, CredentialProps, FolderProps, Inherited, Node, NodeId, NodeKind, Provenance,
    SecretKind, Tree,
};

const NOW: i64 = 1_760_000_000_000;

/// One generated node: where it hangs, what kind it is, and what its port
/// field says.
#[derive(Debug, Clone)]
struct Spec {
    /// Index of the parent, always strictly less than this node's own index,
    /// which is what makes the generated structure acyclic by construction.
    parent: Option<usize>,
    kind: u8,
    field: u8,
    port: u16,
}

fn spec_strategy() -> impl Strategy<Value = (u32, u8, u8, u16)> {
    (any::<u32>(), 0u8..4, 0u8..3, 1u16..=u16::MAX)
}

/// Builds a tree from raw specs. Any node that something else hangs off has to
/// be a folder, so kinds are decided after the shape is known.
fn build(raw: Vec<(u32, u8, u8, u16)>) -> (Tree, Vec<NodeId>) {
    let count = raw.len();
    let mut specs: Vec<Spec> = Vec::with_capacity(count);
    let mut is_parent = vec![false; count];

    for (index, (parent_raw, kind, field, port)) in raw.into_iter().enumerate() {
        // `% (index + 1)` maps 0 to "root" and 1..=index to a preceding node.
        let slot = (parent_raw as usize) % (index + 1);
        let parent = if slot == 0 { None } else { Some(slot - 1) };
        if let Some(parent_index) = parent {
            is_parent[parent_index] = true;
        }
        specs.push(Spec {
            parent,
            kind,
            field,
            port,
        });
    }

    let mut tree = Tree::new();
    let mut ids: Vec<NodeId> = Vec::with_capacity(count);

    for (index, spec) in specs.iter().enumerate() {
        let field = match spec.field {
            0 => Inherited::Inherit,
            1 => Inherited::Default,
            _ => Inherited::Explicit(spec.port),
        };

        let folder = || {
            NodeKind::Folder(FolderProps {
                port: field,
                ..FolderProps::default()
            })
        };

        let kind = if is_parent[index] {
            folder()
        } else {
            match spec.kind {
                0 => folder(),
                1 => {
                    let mut props = ConnectionProps::new("ssh", "host.example").unwrap();
                    props.port = field;
                    NodeKind::Connection(props)
                }
                // Kinds that carry no port at all: the resolver must treat
                // them as transparent rather than as a value of their own.
                2 => NodeKind::Credential(CredentialProps::new(
                    "svc",
                    SecretKind::Agent {
                        comment_filter: None,
                    },
                )),
                _ => NodeKind::Separator,
            }
        };

        let mut node = Node::new(kind, format!("node-{index}"), NOW);
        node.sort_order = index as i64;
        if let Some(parent_index) = spec.parent {
            node.parent_id = Some(ids[parent_index]);
        }
        ids.push(node.id);
        tree.insert(node)
            .expect("generated tree must be insertable");
    }

    (tree, ids)
}

fn arbitrary_tree() -> impl Strategy<Value = (Tree, Vec<NodeId>)> {
    proptest::collection::vec(spec_strategy(), 1..24).prop_map(build)
}

/// The node's port field, or `None` when the kind does not carry one — which
/// the resolver treats identically to `Inherit`.
fn field_of(node: &Node) -> Inherited<u16> {
    node.port_field().copied().unwrap_or(Inherited::Inherit)
}

proptest! {
    /// Whatever the resolver returns was put there by a node on the path from
    /// the node to the root, or is the type default. Nothing is invented.
    #[test]
    fn resolution_is_grounded((tree, ids) in arbitrary_tree()) {
        for id in ids {
            let resolved = tree.resolve_optional(id, Node::port_field).unwrap();
            let path = tree.path_to_root(id).unwrap();

            if let Some(source) = resolved.source() {
                prop_assert!(
                    path.contains(&source),
                    "provenance names {source}, which is not on {path:?}"
                );
            }

            match resolved.value {
                Some(value) => {
                    let source = resolved.source().expect("a value has a source");
                    prop_assert_eq!(
                        field_of(tree.get(source).unwrap()),
                        Inherited::Explicit(value)
                    );
                }
                None => prop_assert!(resolved.provenance.is_default()),
            }
        }
    }

    /// The first field on the path that is not `Inherit` decides the value,
    /// and the provenance names exactly that node. This is the full rule; the
    /// grounding property above is the half of it that matters for safety.
    #[test]
    fn the_nearest_non_inherit_field_wins((tree, ids) in arbitrary_tree()) {
        for id in ids {
            let resolved = tree.resolve_optional(id, Node::port_field).unwrap();
            let path = tree.path_to_root(id).unwrap();

            let deciding = path
                .iter()
                .copied()
                .find(|node_id| !field_of(tree.get(*node_id).unwrap()).is_inherit());

            match deciding {
                Some(node_id) => match field_of(tree.get(node_id).unwrap()) {
                    Inherited::Explicit(value) => {
                        prop_assert_eq!(resolved.value, Some(value));
                        let expected = if node_id == id {
                            Provenance::Own(node_id)
                        } else {
                            Provenance::Ancestor(node_id)
                        };
                        prop_assert_eq!(resolved.provenance, expected);
                    }
                    Inherited::Default => {
                        prop_assert_eq!(resolved.value, None);
                        prop_assert_eq!(resolved.provenance, Provenance::DefaultAt(node_id));
                    }
                    Inherited::Inherit => prop_assert!(false, "find returned an Inherit"),
                },
                None => {
                    prop_assert_eq!(resolved.value, None);
                    prop_assert_eq!(resolved.provenance, Provenance::DefaultAtRoot);
                }
            }
        }
    }

    /// Resolution terminates on every generated tree and gives the same answer
    /// every time. A resolver that walked a parent chain without a bound would
    /// hang here rather than fail.
    #[test]
    fn resolution_is_deterministic_and_terminates((tree, ids) in arbitrary_tree()) {
        for id in &ids {
            let first = tree.resolve_optional(*id, Node::port_field).unwrap();
            let second = tree.resolve_optional(*id, Node::port_field).unwrap();
            prop_assert_eq!(first, second);

            // The defaulting wrapper agrees with the raw walk.
            let defaulted = tree.resolve(*id, Node::port_field).unwrap();
            prop_assert_eq!(defaulted.value, first.value.unwrap_or_default());
            prop_assert_eq!(defaulted.provenance, first.provenance);
        }
    }

    /// Rebuilding the same nodes in a different order produces the same
    /// resolution. Storage hands nodes back in whatever order the query
    /// returns them, so this must not matter.
    #[test]
    fn resolution_does_not_depend_on_insertion_order((tree, ids) in arbitrary_tree()) {
        let before: Vec<_> = ids
            .iter()
            .map(|id| tree.resolve_optional(*id, Node::port_field).unwrap())
            .collect();

        let mut nodes = tree.into_nodes();
        nodes.reverse();
        let rebuilt = Tree::from_nodes(nodes).unwrap();

        let after: Vec<_> = ids
            .iter()
            .map(|id| rebuilt.resolve_optional(*id, Node::port_field).unwrap())
            .collect();

        prop_assert_eq!(before, after);
    }

    /// An effective connection resolves without error for every connection in
    /// an arbitrary tree, and every provenance it reports names a node on that
    /// connection's path to the root.
    #[test]
    fn effective_connections_only_cite_nodes_on_the_path((tree, ids) in arbitrary_tree()) {
        for id in ids {
            let Some(node) = tree.get(id) else { continue };
            if node.kind.as_connection().is_none() {
                continue;
            }
            let effective = tree.effective_connection(id).unwrap();
            let path = tree.path_to_root(id).unwrap();

            for (field, provenance) in effective.provenance() {
                if let Some(source) = provenance.source() {
                    prop_assert!(
                        path.contains(&source),
                        "{field} cites {source}, which is not on {path:?}"
                    );
                }
            }
        }
    }
}
