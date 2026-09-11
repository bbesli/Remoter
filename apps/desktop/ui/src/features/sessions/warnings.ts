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
  | "warning.detail.rdpNlaDisabled"
  | "warning.detail.rdpDisplayControlUnavailable"
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
 * than a key rendered on screen. The constants they mirror are
 * `WARNING_*` in `crates/remoter-proto-vnc` and `crates/remoter-proto-rdp`, and
 * `Exposure::warning_key` in `crates/remoter-proto-vnc/src/security.rs`.
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
  "rdp.network_level_authentication_disabled": "warning.detail.rdpNlaDisabled",
  "rdp.display_control_unavailable": "warning.detail.rdpDisplayControlUnavailable",
};

/**
 * How severe each detail is.
 *
 * A session with no authentication and a session whose bell rang must not draw
 * the same box. The default for an unrecognised key is `warning`: an adapter
 * raised it deliberately, and treating the unknown as harmless is how a real
 * one gets lost among the noise.
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
  "rdp.network_level_authentication_disabled": "danger",
  "rdp.display_control_unavailable": "info",
};

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
