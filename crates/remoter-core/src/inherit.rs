//! Three-state property inheritance and its resolver.
//!
//! Every inheritable field is an [`Inherited<T>`]. Resolution walks from the
//! node towards the root and takes the first field that is not `Inherit`. The
//! result is a [`Resolved<T>`], which carries the value *and* the node it came
//! from.
//!
//! The provenance is not decoration. Inheritance without a visible origin is
//! the single most common source of "why did it connect as the wrong user?" in
//! tools that have this feature, so the origin is part of the resolver's
//! return type rather than something an interface has to reconstruct.

use serde::{Deserialize, Serialize};

use crate::node::{Node, NodeId};

/// A field that may take its value from an ancestor.
///
/// Note the distinction between the two non-`Explicit` states.
/// `Inherit` keeps looking upwards; `Default` stops the walk and pins the
/// type's default at this node, which is how a user says "this subtree is
/// deliberately plain" without having to type the default out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Inherited<T> {
    /// Take the nearest ancestor's effective value.
    Inherit,
    /// Use this value, and pass it down to descendants.
    Explicit(T),
    /// Use the type's default and stop inheriting here.
    Default,
}

impl<T> Default for Inherited<T> {
    /// `Inherit`, so that a newly created node changes nothing about its
    /// subtree until the user says otherwise.
    fn default() -> Self {
        Self::Inherit
    }
}

impl<T> Inherited<T> {
    /// The explicitly set value, if this field carries one.
    pub const fn explicit(&self) -> Option<&T> {
        match self {
            Self::Explicit(v) => Some(v),
            Self::Inherit | Self::Default => None,
        }
    }

    /// Whether this field carries an explicit value.
    pub const fn is_explicit(&self) -> bool {
        matches!(self, Self::Explicit(_))
    }

    /// Whether this field defers to an ancestor.
    pub const fn is_inherit(&self) -> bool {
        matches!(self, Self::Inherit)
    }

    /// Whether this field pins the type default.
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::Default)
    }

    /// Applies `f` to an explicit value, preserving the other two states.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Inherited<U> {
        match self {
            Self::Inherit => Inherited::Inherit,
            Self::Default => Inherited::Default,
            Self::Explicit(v) => Inherited::Explicit(f(v)),
        }
    }
}

/// Where a resolved value came from.
///
/// `Copy`, because interfaces pass it around per field and per row.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Provenance {
    /// The node set the value itself.
    Own(NodeId),
    /// An ancestor set the value; this is its id.
    Ancestor(NodeId),
    /// This node stopped the walk and pinned the type default.
    DefaultAt(NodeId),
    /// Nothing on the path from the node to the root supplied a value, so the
    /// type default applies.
    DefaultAtRoot,
}

impl Provenance {
    /// The node that supplied the value, or `None` when the default applied
    /// because the walk reached the root.
    pub const fn source(&self) -> Option<NodeId> {
        match self {
            Self::Own(id) | Self::Ancestor(id) | Self::DefaultAt(id) => Some(*id),
            Self::DefaultAtRoot => None,
        }
    }

    /// Whether the value came from an ancestor rather than the node itself.
    ///
    /// This is what decides whether the interface shows the "Inherited from …
    /// [Override here]" affordance.
    pub const fn is_inherited(&self) -> bool {
        matches!(self, Self::Ancestor(_))
    }

    /// Whether the value is a type default rather than something anyone set.
    pub const fn is_default(&self) -> bool {
        matches!(self, Self::DefaultAt(_) | Self::DefaultAtRoot)
    }
}

/// A value together with the node it came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Resolved<T> {
    /// The effective value.
    pub value: T,
    /// Where it came from.
    pub provenance: Provenance,
}

impl<T> Resolved<T> {
    /// Pairs a value with its origin.
    pub const fn new(value: T, provenance: Provenance) -> Self {
        Self { value, provenance }
    }

    /// The node set this value itself.
    pub const fn own(node: NodeId, value: T) -> Self {
        Self::new(value, Provenance::Own(node))
    }

    /// An ancestor set this value.
    pub const fn from_ancestor(node: NodeId, value: T) -> Self {
        Self::new(value, Provenance::Ancestor(node))
    }

    /// `node` pinned the type default.
    pub const fn default_at(node: NodeId, value: T) -> Self {
        Self::new(value, Provenance::DefaultAt(node))
    }

    /// The walk reached the root without finding a value.
    pub const fn default_at_root(value: T) -> Self {
        Self::new(value, Provenance::DefaultAtRoot)
    }

    /// The node that supplied the value, if any.
    pub const fn source(&self) -> Option<NodeId> {
        self.provenance.source()
    }

    /// Whether the value came from an ancestor.
    pub const fn is_inherited(&self) -> bool {
        self.provenance.is_inherited()
    }

    /// Whether the value is a type default.
    pub const fn is_default(&self) -> bool {
        self.provenance.is_default()
    }

    /// Transforms the value, keeping the provenance.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Resolved<U> {
        Resolved {
            value: f(self.value),
            provenance: self.provenance,
        }
    }

    /// Borrows the value, keeping the provenance.
    pub const fn as_ref(&self) -> Resolved<&T> {
        Resolved {
            value: &self.value,
            provenance: self.provenance,
        }
    }

    /// Discards the provenance.
    pub fn into_value(self) -> T {
        self.value
    }
}

/// Walks `node` then `ancestors` (ordered nearest → root) and returns the
/// first value that is not `Inherit`, with the node that supplied it.
///
/// A pure function: no I/O, no clock, no tree. The only allocation is the
/// clone of the value that wins, which is what makes exhaustive property
/// testing of the inheritance rules cheap.
///
/// `field` returns `Option` so that node kinds which do not carry the field at
/// all — a separator has no port — are treated as `Inherit` without every kind
/// having to store every inheritable field.
///
/// The value is `Option<T>` rather than `T` so that the resolver works for
/// types with no meaningful default, such as a credential reference. `None`
/// means "the default applies"; the caller decides what that default is,
/// because for a port it depends on the protocol.
pub(crate) fn resolve<T, F>(node: &Node, ancestors: &[&Node], field: F) -> Resolved<Option<T>>
where
    T: Clone,
    F: for<'a> Fn(&'a Node) -> Option<&'a Inherited<T>>,
{
    match field(node) {
        Some(Inherited::Explicit(v)) => Resolved::own(node.id, Some(v.clone())),
        Some(Inherited::Default) => Resolved::default_at(node.id, None),
        Some(Inherited::Inherit) | None => {
            for ancestor in ancestors {
                match field(ancestor) {
                    Some(Inherited::Explicit(v)) => {
                        return Resolved::from_ancestor(ancestor.id, Some(v.clone()));
                    }
                    Some(Inherited::Default) => return Resolved::default_at(ancestor.id, None),
                    Some(Inherited::Inherit) | None => continue,
                }
            }
            Resolved::default_at_root(None)
        }
    }
}

/// Walks `node` then `ancestors` for the nearest field that is `Some`.
///
/// Presentation fields — icon, colour — are plain `Option`s on `Node` rather
/// than `Inherited`, because the data model defines them that way. `None`
/// there means "not set here", which for inheritance purposes is the same as
/// `Inherit`, so they resolve by nearest-`Some` instead of by three-state.
pub(crate) fn resolve_optional_field<T, F>(
    node: &Node,
    ancestors: &[&Node],
    field: F,
) -> Resolved<Option<T>>
where
    T: Clone,
    F: for<'a> Fn(&'a Node) -> Option<&'a T>,
{
    if let Some(v) = field(node) {
        return Resolved::own(node.id, Some(v.clone()));
    }
    for ancestor in ancestors {
        if let Some(v) = field(ancestor) {
            return Resolved::from_ancestor(ancestor.id, Some(v.clone()));
        }
    }
    Resolved::default_at_root(None)
}
