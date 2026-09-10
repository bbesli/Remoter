/**
 * Query keys for the audit log.
 *
 * They belong in `lib/queryKeys.ts` with every other key, and that is where
 * they should end up. They are here because this feature was written while
 * other screens were being written in the same tree, and a shared file that
 * four authors rewrite at once is the one file most likely to lose an edit.
 * The rule the central file exists to enforce — no key literal at a call site,
 * one place that knows the whole family — is kept: nothing outside this module
 * writes an audit key, and `all()` is a prefix of the other two so a single
 * invalidation covers the feature.
 *
 * Folding this into `qk` is a one-line move once the tree is quiet.
 */

import type { AuditQuery } from "@/lib/ipc";

export const auditKeys = {
  /** Everything the audit screen reads. Invalidate this after an export. */
  all: () => ["audit"] as const,
  /** The filter vocabulary the core reports. */
  filters: () => ["audit", "filters"] as const,
  /**
   * One page of entries. The whole query object is part of the key — including
   * its paging — because two pages of the same filter are two different
   * answers, and the screen holds both while the viewport straddles them.
   */
  page: (query: AuditQuery) => ["audit", "page", query] as const,
} as const;
