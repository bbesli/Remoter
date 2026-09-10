//! Property tests for moving nodes.
//!
//! The structural invariant a connection tree lives or dies by is that it is a
//! tree. Re-parenting is the only operation that can break it, so it is the
//! one tested against arbitrary inputs and arbitrary sequences.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashSet;

use proptest::prelude::*;
use remoter_core::{ConnectionProps, CoreError, Node, NodeId, NodeKind, Tree};

const NOW: i64 = 1_760_000_000_000;

/// Builds an arbitrary tree. Parents are always earlier in the vector, which
/// makes the generated structure acyclic before any move is attempted; the
/// moves are what the properties are actually about.
fn build(raw: Vec<(u32, bool)>) -> (Tree, Vec<NodeId>) {
    let count = raw.len();
    let mut parents: Vec<Option<usize>> = Vec::with_capacity(count);
    let mut is_parent = vec![false; count];

    for (index, (parent_raw, _)) in raw.iter().enumerate() {
        let slot = (*parent_raw as usize) % (index + 1);
        let parent = if slot == 0 { None } else { Some(slot - 1) };
        if let Some(parent_index) = parent {
            is_parent[parent_index] = true;
        }
        parents.push(parent);
    }

    let mut tree = Tree::new();
    let mut ids = Vec::with_capacity(count);

    for (index, (_, leafish)) in raw.into_iter().enumerate() {
        // A node with children has to be a folder. The rest are folders or
        // connections, so that `NotAContainer` is reachable.
        let kind = if is_parent[index] || !leafish {
            NodeKind::folder()
        } else {
            NodeKind::Connection(ConnectionProps::new("ssh", "host.example").unwrap())
        };
        let mut node = Node::new(kind, format!("node-{index}"), NOW);
        node.sort_order = index as i64;
        if let Some(parent_index) = parents[index] {
            node.parent_id = Some(ids[parent_index]);
        }
        ids.push(node.id);
        tree.insert(node)
            .expect("generated tree must be insertable");
    }

    (tree, ids)
}

fn arbitrary_tree() -> impl Strategy<Value = (Tree, Vec<NodeId>)> {
    proptest::collection::vec((any::<u32>(), any::<bool>()), 1..20).prop_map(build)
}

/// Every node's path to the root terminates and visits nothing twice.
fn assert_still_a_tree(tree: &Tree) -> Result<(), TestCaseError> {
    for node in tree.nodes() {
        let path = tree.path_to_root(node.id).map_err(|error| {
            TestCaseError::fail(format!("path from {} failed: {error}", node.id))
        })?;
        let unique: HashSet<NodeId> = path.iter().copied().collect();
        prop_assert_eq!(unique.len(), path.len(), "path repeats a node");
        prop_assert_eq!(path[0], node.id);
        prop_assert!(!tree.is_ancestor_of(node.id, node.id).unwrap());
    }
    Ok(())
}

proptest! {
    /// A move either succeeds and leaves a tree, or is rejected. It never
    /// leaves a cycle behind, and it never half-applies.
    #[test]
    fn a_sequence_of_moves_never_creates_a_cycle(
        (mut tree, ids) in arbitrary_tree(),
        moves in proptest::collection::vec((any::<u32>(), any::<u32>(), any::<i64>()), 1..12),
    ) {
        for (node_raw, target_raw, sort_order) in moves {
            let node = ids[(node_raw as usize) % ids.len()];
            let slot = (target_raw as usize) % (ids.len() + 1);
            let target = if slot == 0 { None } else { Some(ids[slot - 1]) };

            let before_parent = tree.get(node).unwrap().parent_id;
            let would_cycle = match target {
                Some(target_id) => {
                    target_id == node || tree.is_ancestor_of(node, target_id).unwrap()
                }
                None => false,
            };
            let target_is_container = target.is_none_or(|target_id| {
                tree.get(target_id).unwrap().kind.is_container()
            });

            let result = tree.move_node(node, target, sort_order);

            match result {
                Ok(patch) => {
                    prop_assert!(!would_cycle, "a cycle-forming move succeeded");
                    prop_assert!(target_is_container);
                    // The point of a parent pointer: one row, whatever the
                    // size of the subtree that moved with it.
                    prop_assert_eq!(patch.rows_touched(), 1);
                    prop_assert_eq!(patch.updated, vec![node]);
                    prop_assert_eq!(tree.get(node).unwrap().parent_id, target);
                    prop_assert_eq!(tree.get(node).unwrap().sort_order, sort_order);
                    prop_assert!(tree.children(target).contains(&node));
                }
                Err(CoreError::Cycle { node: reported, parent }) => {
                    prop_assert!(would_cycle, "a legal move was rejected as a cycle");
                    prop_assert_eq!(reported, node);
                    prop_assert_eq!(Some(parent), target);
                    // A rejected move changes nothing.
                    prop_assert_eq!(tree.get(node).unwrap().parent_id, before_parent);
                }
                Err(CoreError::NotAContainer(_)) => {
                    prop_assert!(!target_is_container);
                    prop_assert_eq!(tree.get(node).unwrap().parent_id, before_parent);
                }
                Err(other) => return Err(TestCaseError::fail(format!("unexpected error: {other}"))),
            }

            assert_still_a_tree(&tree)?;
        }
    }

    /// Moving a node under any of its own descendants is always refused, and
    /// moving it under anything else is not refused for that reason.
    #[test]
    fn a_node_may_never_be_moved_into_its_own_subtree((mut tree, ids) in arbitrary_tree()) {
        for node in ids {
            let subtree = tree.subtree(node).unwrap();
            for target in &subtree {
                let error = tree.move_node(node, Some(*target), 0).unwrap_err();
                prop_assert_eq!(
                    error,
                    CoreError::Cycle {
                        node,
                        parent: *target
                    }
                );
            }

            // Everything outside the subtree that is a folder accepts it.
            let outside: Vec<NodeId> = tree
                .nodes()
                .filter(|candidate| {
                    !subtree.contains(&candidate.id) && candidate.kind.is_container()
                })
                .map(|candidate| candidate.id)
                .collect();
            for target in outside {
                prop_assert!(tree.move_node(node, Some(target), 0).is_ok());
                assert_still_a_tree(&tree)?;
            }
        }
    }

    /// A move preserves the subtree it moves: the same descendants, in the
    /// same order, under a new parent.
    #[test]
    fn a_move_carries_its_subtree_unchanged((mut tree, ids) in arbitrary_tree()) {
        for node in ids {
            let before = tree.descendants(node).unwrap();
            let candidates: Vec<NodeId> = tree
                .nodes()
                .filter(|candidate| candidate.kind.is_container())
                .map(|candidate| candidate.id)
                .filter(|candidate| !before.contains(candidate) && *candidate != node)
                .collect();

            for target in candidates {
                tree.move_node(node, Some(target), 0).unwrap();
                prop_assert_eq!(tree.descendants(node).unwrap(), before.clone());
                prop_assert_eq!(tree.get(node).unwrap().parent_id, Some(target));
            }

            tree.move_node(node, None, 0).unwrap();
            prop_assert_eq!(tree.descendants(node).unwrap(), before);
        }
    }
}
