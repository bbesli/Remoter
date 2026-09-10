//! The bounds every parser in this crate works inside.
//!
//! `docs/features/import-export.md` requires a hard cap on document size,
//! element count and nesting depth, and bounded buffers throughout. Collecting
//! the numbers in one struct means a fuzz target can shrink them all at once,
//! and means no parser can grow a private limit that nobody reviews.
//!
//! The defaults are sized for the case the feature exists for: an estate of a
//! few thousand connections exported by a tool that writes forty attributes per
//! node. They are generous for a real file and small enough that the worst case
//! is a refusal rather than a machine that stops responding.

/// Bounds applied to every parse.
///
/// Public fields with no `#[non_exhaustive]`: a caller tightening one limit
/// writes `Limits { max_nodes: 500, ..Limits::new() }`, and making that the
/// natural spelling is worth more than the freedom to add a field without a
/// version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// Maximum size of the input, in bytes.
    pub max_input_bytes: usize,
    /// Maximum nesting depth of an XML document or a folder path.
    pub max_depth: usize,
    /// Maximum number of XML elements, CSV records or config lines.
    pub max_items: usize,
    /// Maximum number of attributes on one XML element.
    pub max_attributes: usize,
    /// Maximum length of one attribute value, CSV field or config line, in
    /// bytes.
    pub max_value_bytes: usize,
    /// Maximum number of nodes the preview may contain.
    pub max_nodes: usize,
    /// Maximum number of findings recorded before the report stops growing.
    pub max_findings: usize,
    /// Maximum number of custom fields carried on one node.
    pub max_custom_fields: usize,
    /// Maximum number of files an `Include` chain may pull in.
    pub max_included_files: usize,
    /// Maximum nesting of `Include` directives.
    pub max_include_depth: usize,
}

impl Limits {
    /// The defaults, as a `const` so a caller can build one at compile time.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            max_input_bytes: 32 * 1024 * 1024,
            max_depth: 64,
            max_items: 200_000,
            max_attributes: 256,
            max_value_bytes: 64 * 1024,
            max_nodes: 100_000,
            max_findings: 4096,
            max_custom_fields: 128,
            max_included_files: 64,
            max_include_depth: 8,
        }
    }

    /// Much tighter bounds, for a fuzz target: the interesting failures are at
    /// the edges, and a fuzzer that has to build a 32 MiB input to reach one
    /// will never reach it.
    #[must_use]
    pub const fn small() -> Self {
        Self {
            max_input_bytes: 64 * 1024,
            max_depth: 16,
            max_items: 2_000,
            max_attributes: 32,
            max_value_bytes: 4096,
            max_nodes: 2_000,
            max_findings: 64,
            max_custom_fields: 16,
            max_included_files: 4,
            max_include_depth: 3,
        }
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[allow(clippy::panic, reason = "test code")]
mod tests {
    use super::*;

    #[test]
    fn depth_limit_does_not_exceed_the_domain_model() {
        // A document allowed to nest deeper than the tree can hold would parse
        // and then fail at insert time, which is a worse error than a refusal.
        assert!(Limits::new().max_depth <= remoter_core::MAX_TREE_DEPTH);
        assert!(Limits::small().max_depth <= remoter_core::MAX_TREE_DEPTH);
    }

    #[test]
    fn small_is_smaller_than_the_default_everywhere() {
        let d = Limits::new();
        let s = Limits::small();
        assert!(s.max_input_bytes < d.max_input_bytes);
        assert!(s.max_depth < d.max_depth);
        assert!(s.max_items < d.max_items);
        assert!(s.max_attributes < d.max_attributes);
        assert!(s.max_value_bytes < d.max_value_bytes);
        assert!(s.max_nodes < d.max_nodes);
        assert!(s.max_findings < d.max_findings);
        assert!(s.max_custom_fields < d.max_custom_fields);
        assert!(s.max_included_files < d.max_included_files);
        assert!(s.max_include_depth < d.max_include_depth);
    }
}
