/**
 * Which open session can have a file pane docked under it, and why not.
 *
 * Two mount points ask the same question and must not answer it differently:
 * the tab strip decides whether its Files control does anything, and the main
 * window decides which docks to mount. A control that is enabled over a session
 * the window then refuses to dock — or a dock that appears with no control that
 * opened it — is the same defect from either side, so the rule lives here and
 * both read it.
 *
 * The capability comes from the adapter's own report rather than from the
 * protocol name, so a plugin protocol that carries files is treated exactly as
 * SSH is, and RDP is refused by the same rule that lets SSH through.
 */

import type { SessionRecord } from "@/features/sessions";

/**
 * Why this session has no file pane to offer. `null` means it has one.
 *
 * A string rather than a boolean because a disabled control has to say why:
 * "why not?" is the only question a dead button raises, and the four reasons
 * need four different sentences.
 */
export type FilePaneBlocker =
  /** No tab is in front at all. */
  | "noSession"
  /** The tab is still connecting, or its session has ended. */
  | "notRunning"
  /** The adapter reports no file channel — an RDP or VNC session. */
  | "noFileChannel"
  /** The whole tab is already a file session; there is nothing to dock it under. */
  | "isFileSession";

export function filePaneBlocker(record: SessionRecord | undefined): FilePaneBlocker | null {
  if (record === undefined) return "noSession";
  // `opened` is null until the core reports the session ready, and the id is
  // null again once it has closed. Either way there is no channel to open.
  if (record.phase !== "running" || record.sessionId === null || record.opened === null) {
    return "notRunning";
  }
  if (record.opened.capabilities.kind === "file_transfer") return "isFileSession";
  if (!record.opened.capabilities.fileTransfer) return "noFileChannel";
  return null;
}

/** Whether a pane may be docked under this session right now. */
export function canDockFilePane(record: SessionRecord | undefined): boolean {
  return filePaneBlocker(record) === null;
}
