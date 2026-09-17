/**
 * What a session warning says, and how loudly.
 *
 * `store.ts` has accumulated `SessionWarning`s since the session feature was
 * written and nothing has ever rendered them. They are not decoration: a VNC
 * server that negotiated no authentication at all, an RDP connection running
 * without Network Level Authentication, a clear-text RFB session to a routable
 * address — each of those is a security fact about the session the user is
 * looking at, and each of them arrived, was stored, and was thrown away when
 * the tab closed.
 *
 * This module turns one into something the surface can draw. It is a pure
 * function so it can be tested without a catalogue and without a DOM.
 *
 * # Two kinds of `detail`, and they must not be confused
 *
 * `SessionWarning.detail` carries different things depending on the kind:
 *
 * - for `unencrypted_transport` and `other` it is a **catalogue key** chosen by
 *   the adapter — `vnc.security.none`, `rdp.display_control_unavailable`. It is
 *   ours, it is finite, and it is translated.
 * - for `weak_algorithm` it is an **algorithm name as it appeared on the wire**.
 *   Not ours. Shown as an isolated value inside a translated sentence.
 * - for `banner` it is the **server's message of the day**: remote, untrusted,
 *   arbitrary length, arbitrary script. Shown verbatim as text, never as
 *   markup, in its own block rather than spliced into a sentence.
 *
 * A detail the interface has no sentence for is shown *as its key* rather than
 * suppressed. An adapter that adds a warning nobody wrote copy for should look
 * unfinished, not silent.
 */

import type { CalloutTone } from "@/components/Callout";
import type { SessionWarning } from "./store";

/**
 * Every sentence this module can ask for.
 *
 * A union rather than `string`, so the catalogue's own types check it: a key
 * with no copy written for it is a compile error here rather than a humanised
 * key on screen next to the words "not authenticated".
 */
export type WarningKey =
  | "warning.detail.vncCleartextLoopback"
  | "warning.detail.vncCleartextPrivateNetwork"
  | "warning.detail.vncCleartextRoutable"
  | "warning.detail.vncSecurityNone"
  | "warning.detail.vncVersionLegacy"
  | "warning.detail.vncPasswordTruncated"
  | "warning.detail.vncBell"
  | "warning.detail.vncClipboardSubstituted"
  | "warning.detail.vncClipboardMangled"
  | "warning.detail.vncButtonUnsupported"
  | "warning.detail.vncResizeUnsupported"
  | "warning.detail.vncInputUnsupported"
  | "warning.detail.vncClipboardViewOnly"
  | "warning.detail.vncClipboardRefused"
  | "warning.detail.vncClipboardUnsupported"
  | "warning.detail.rdpNlaDisabled"
  | "warning.detail.rdpKeyboardLayoutGuessed"
  | "warning.detail.rdpDisplayControlUnavailable"
  | "warning.detail.rdpClipboardTooLarge"
  | "warning.detail.rdpClipboardUnavailable"
  | "warning.detail.localClipboardWriteFailed"
  | "warning.detail.sshAgentForwarding"
  | "warning.detail.sshInputUnsupported"
  | "warning.detail.sshClipboardRefused"
  | "warning.detail.sshClipboardUnsupported"
  | "warning.kind.unencryptedTransport"
  | "warning.kind.weakAlgorithm"
  | "warning.kind.recordingStarted"
  | "warning.kind.outputThrottled"
  | "warning.kind.banner"
  | "warning.kind.other";

/**
 * Catalogue keys for the details the adapters actually emit.
 *
 * Written out rather than derived from the wire string, so that a translator
 * sees a finite list and a new adapter warning is a missing entry here rather
 * than a key rendered on screen.
 *
 * **This table is the whole set, and the whole set was checked against the
 * adapters.** Five of these — the VNC refusals, from `resize_unsupported` down
 * to `clipboard_unsupported` — were absent, which meant a VNC session that
 * refused a paste put the string `vnc.clipboard.policy_refused` on screen
 * inside a box that otherwise contains sentences. The SSH block was absent for
 * the same reason and is not a VNC or RDP matter at all: an SSH tab is where
 * `ssh.agent_forwarding_enabled` shows up, and that one is a security fact.
 *
 * The constants mirrored here are:
 *
 * - `WARNING_*` in `crates/remoter-proto-vnc/src/{protocol,session}.rs`
 * - `Exposure::warning_key` in `crates/remoter-proto-vnc/src/security.rs`
 * - `WARNING_*` in `crates/remoter-proto-rdp/src/{protocol,session,clipboard}.rs`
 * - `WARNING_LOCAL_CLIPBOARD_FAILED` in `crates/remoter-ipc/src/session.rs`, which
 *   is raised by the core rather than by an adapter
 * - `WARNING_*` in `crates/remoter-proto-ssh/src/session.rs`
 *
 * The one thing not here is `WARNING_EXIT_SIGNAL_PREFIX`, whose details carry a
 * signal name after the prefix. See the note below the tones.
 */
const DETAIL_KEYS: Readonly<Record<string, WarningKey>> = {
  "vnc.cleartext.loopback": "warning.detail.vncCleartextLoopback",
  "vnc.cleartext.private_network": "warning.detail.vncCleartextPrivateNetwork",
  "vnc.cleartext.routable": "warning.detail.vncCleartextRoutable",
  "vnc.security.none": "warning.detail.vncSecurityNone",
  "vnc.version.legacy": "warning.detail.vncVersionLegacy",
  "vnc.password_truncated": "warning.detail.vncPasswordTruncated",
  "vnc.bell": "warning.detail.vncBell",
  "vnc.clipboard.substituted": "warning.detail.vncClipboardSubstituted",
  "vnc.clipboard.inbound_mangled": "warning.detail.vncClipboardMangled",
  "vnc.pointer.button_unsupported": "warning.detail.vncButtonUnsupported",
  "vnc.resize_unsupported": "warning.detail.vncResizeUnsupported",
  "vnc.input_unsupported": "warning.detail.vncInputUnsupported",
  "vnc.clipboard.view_only": "warning.detail.vncClipboardViewOnly",
  "vnc.clipboard.policy_refused": "warning.detail.vncClipboardRefused",
  "vnc.clipboard_unsupported": "warning.detail.vncClipboardUnsupported",
  "rdp.network_level_authentication_disabled": "warning.detail.rdpNlaDisabled",
  "rdp.keyboard_layout_guessed": "warning.detail.rdpKeyboardLayoutGuessed",
  "rdp.display_control_unavailable": "warning.detail.rdpDisplayControlUnavailable",
  "rdp.clipboard_too_large": "warning.detail.rdpClipboardTooLarge",
  "rdp.clipboard_unavailable": "warning.detail.rdpClipboardUnavailable",
  "clipboard.local_write_failed": "warning.detail.localClipboardWriteFailed",
  "ssh.agent_forwarding_enabled": "warning.detail.sshAgentForwarding",
  "ssh.input_unsupported": "warning.detail.sshInputUnsupported",
  "ssh.clipboard.policy_refused": "warning.detail.sshClipboardRefused",
  "ssh.clipboard_unsupported": "warning.detail.sshClipboardUnsupported",
};

/**
 * How severe each detail is.
 *
 * A session with no authentication and a session whose bell rang must not draw
 * the same box. The default for an unrecognised key is `warning`: an adapter
 * raised it deliberately, and treating the unknown as harmless is how a real
 * one gets lost among the noise.
 *
 * The refusals — a paste the policy stopped, a resize the server cannot do —
 * are `info`. Nothing is unprotected; a control the user reached for did not
 * work, and the sentence says why. `ssh.agent_forwarding_enabled` is the
 * exception in that block: forwarding the agent hands the remote host the use
 * of every key in it for as long as the session lasts, which is a decision
 * worth seeing again on the screen where it took effect.
 */
const DETAIL_TONES: Readonly<Record<string, CalloutTone>> = {
  "vnc.cleartext.loopback": "info",
  "vnc.cleartext.private_network": "warning",
  "vnc.cleartext.routable": "danger",
  "vnc.security.none": "danger",
  "vnc.version.legacy": "warning",
  "vnc.password_truncated": "warning",
  "vnc.bell": "info",
  "vnc.clipboard.substituted": "info",
  "vnc.clipboard.inbound_mangled": "info",
  "vnc.pointer.button_unsupported": "info",
  "vnc.resize_unsupported": "info",
  "vnc.input_unsupported": "info",
  "vnc.clipboard.view_only": "info",
  "vnc.clipboard.policy_refused": "info",
  "vnc.clipboard_unsupported": "info",
  "rdp.network_level_authentication_disabled": "danger",
  // Not `info`. Nothing is unprotected, but every keystroke in the session is
  // being decoded by the wrong layout and the protocol reports no fault for
  // it — the user's own conclusion is that their keyboard is broken.
  "rdp.keyboard_layout_guessed": "warning",
  "rdp.display_control_unavailable": "info",
  "rdp.clipboard_too_large": "info",
  "rdp.clipboard_unavailable": "info",
  // Not `info`: the next paste on this machine will silently produce the wrong
  // text, and the user has no other way to find out.
  "clipboard.local_write_failed": "warning",
  "ssh.agent_forwarding_enabled": "warning",
  "ssh.input_unsupported": "info",
  "ssh.clipboard.policy_refused": "info",
  "ssh.clipboard_unsupported": "info",
};

/**
 * `WARNING_EXIT_SIGNAL_PREFIX` is deliberately **not** covered here, and this
 * note is the record of that decision.
 *
 * Its details are `ssh.exit_signal.SEGV` and `ssh.exit_signal.SEGV.core` — a
 * family, not a key, with the signal name inside the token. Covering it means
 * interpolating that name into a sentence, which means a second interpolated
 * value on `WarningView` and a second branch in the component that renders one.
 * Those are worth doing; they were not done here because the component is being
 * rewritten alongside this change and a field with no renderer is exactly the
 * defect this file is being fixed for.
 *
 * Until then it falls through to the unnamed path and is shown as the key it
 * is, which is what that path exists for.
 */

/** One warning, ready to draw. */
export interface WarningView {
  /** The catalogue key for the sentence. */
  key: WarningKey;
  /** The wire-named algorithm, for the one sentence that interpolates one. */
  algorithm: string | null;
  /** Remote text, shown verbatim in its own block. Untrusted. */
  remoteText: string | null;
  /** A detail key the interface has no sentence for. Shown as itself. */
  unnamedDetail: string | null;
  tone: CalloutTone;
}

/** What one warning says. */
export function describeWarning(warning: SessionWarning): WarningView {
  const detail = warning.detail;

  switch (warning.kind) {
    case "unencrypted_transport":
    case "other": {
      const key = detail === null ? undefined : DETAIL_KEYS[detail];
      if (key !== undefined && detail !== null) {
        return {
          key,
          algorithm: null,
            remoteText: null,
          unnamedDetail: null,
          tone: DETAIL_TONES[detail] ?? "warning",
        };
      }
      return {
        key: warning.kind === "other" ? "warning.kind.other" : "warning.kind.unencryptedTransport",
        algorithm: null,
        remoteText: null,
        unnamedDetail: detail,
        tone: warning.kind === "other" ? "warning" : "danger",
      };
    }

    case "weak_algorithm":
      return {
        key: "warning.kind.weakAlgorithm",
        algorithm: detail,
        remoteText: null,
        unnamedDetail: null,
        tone: "warning",
      };

    case "recording_started":
      return {
        key: "warning.kind.recordingStarted",
        algorithm: null,
        remoteText: null,
        unnamedDetail: null,
        tone: "warning",
      };

    case "output_throttled":
      return {
        key: "warning.kind.outputThrottled",
        algorithm: null,
        remoteText: null,
        unnamedDetail: null,
        tone: "info",
      };

    case "banner":
      return {
        key: "warning.kind.banner",
        algorithm: null,
        remoteText: detail,
        unnamedDetail: null,
        tone: "info",
      };

    default:
      // A kind the core added that this build has no word for. Named rather
      // than dropped, for the same reason an unknown detail is.
      return {
        key: "warning.kind.other",
        algorithm: null,
        remoteText: null,
        unnamedDetail: detail ?? warning.kind,
        tone: "warning",
      };
  }
}

/** The loudest tone in a set, for the collapsed summary's colour. */
export function loudestTone(views: readonly WarningView[]): CalloutTone {
  if (views.some((view) => view.tone === "danger")) return "danger";
  if (views.some((view) => view.tone === "warning")) return "warning";
  if (views.some((view) => view.tone === "info")) return "info";
  return "neutral";
}

/**
 * Whether a set may be collapsed out of the way.
 *
 * It may not while any of it is `danger`. A warning that a session has no
 * authentication at all, hidden behind a chevron the user clicked once, is a
 * warning that was not shown — and this application has already shipped one
 * control that did nothing.
 */
export function canCollapse(views: readonly WarningView[]): boolean {
  return !views.some((view) => view.tone === "danger");
}
