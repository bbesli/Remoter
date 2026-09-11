/**
 * The status line for whatever occupies the session area.
 *
 * With a session in front it carries that session's telemetry — state,
 * address, echo latency, throughput, terminal size — and every figure in it is
 * one the interface measured or the core reported. With no session it falls
 * back to what is true instead: which connection is selected and where it
 * would connect to.
 */

import { Icon } from "@/components/Icon";
import { SessionStatus } from "@/features/sessions";
import type { SessionRecord } from "@/features/sessions";
import { isolate, isolateChain, isolateLtr, useT } from "@/i18n";
import type { EffectiveConnection, IpcFailure, TreeNode } from "@/lib/ipc";
import s from "./StatusBar.module.css";

interface StatusBarProps {
  /**
   * The session in front, when there is one. It wins over the tree selection:
   * the bar describes what fills the session area, and that is the session.
   */
  session?: SessionRecord | undefined;
  node: TreeNode | undefined;
  effective: EffectiveConnection | undefined;
  resolving: boolean;
  /**
   * Set when resolution was refused. The inspector shows the whole failure,
   * but it is closed by default — so the bar carries the core's sentence
   * rather than the old "unavailable", which said nothing about why.
   */
  error?: IpcFailure | null | undefined;
  /** Opens the inspector, where the detail and the suggested actions are. */
  onShowDetail?: (() => void) | null | undefined;
}

/** Reads a field out of a resolved connection without assuming it is present. */
function field(effective: EffectiveConnection | undefined, name: string): string | null {
  const found = effective?.fields.find((f) => f.field === name);
  return found?.value ?? null;
}

export function StatusBar({
  session,
  node,
  effective,
  resolving,
  error = null,
  onShowDetail = null,
}: StatusBarProps) {
  const t = useT("shell");
  const tCommon = useT("common");

  if (session !== undefined) {
    return (
      <div className={s.bar} role="status">
        <SessionStatus record={session} />
      </div>
    );
  }

  if (!node) {
    return (
      <div className={s.bar} role="status">
        <span className={s.dot} data-state="idle" aria-hidden="true" />
        <span className={s.state}>{t("statusBar.nothingSelected")}</span>
      </div>
    );
  }

  const host = field(effective, "host") ?? node.host;
  const port = field(effective, "port") ?? (node.port === null ? null : String(node.port));
  const username = field(effective, "username") ?? node.username;
  const protocol = effective?.protocol ?? node.protocol ?? t("statusBar.protocolUnset");
  // An address is LTR by specification whatever characters it contains, and a
  // jump-host chain reads in the order it is written. Both are isolated so an
  // Arabic interface — or one Arabic character inside a hostname — cannot
  // reorder them. See src/i18n/bidi.ts.
  const address = host === null ? null : port === null ? host : `${host}:${port}`;
  const hops = effective?.gatewayChain ?? [];
  const hopChain = isolateChain(hops, tCommon("punctuation.chainSeparator"));

  return (
    <div className={s.bar} role="status">
      <span className={s.dot} data-state="idle" aria-hidden="true" />
      <span className={s.state}>{t("statusBar.noSession")}</span>

      <span className={s.sep} aria-hidden="true">
        ·
      </span>
      <span className={s.mono}>{isolateLtr(protocol)}</span>

      {address !== null && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>{isolateLtr(address)}</span>
        </>
      )}

      {username !== null && username !== "" && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.mono}>{isolate(username)}</span>
        </>
      )}

      {hops.length > 0 && (
        <>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.hops} title={hopChain}>
            <Icon name="shield" size={12} />
            <span className={s.mono}>{hopChain}</span>
          </span>
        </>
      )}

      <div className={s.spacer} />

      {error !== null ? (
        // The bar is already a live region; a nested alert would announce twice.
        <span className={s.failure} title={error.message}>
          <Icon name="alert" size={12} />
          <span className={s.failureText}>{error.message}</span>
          {onShowDetail !== null && (
            <button type="button" className={s.failureLink} onClick={onShowDetail}>
              {t("statusBar.showDetail")}
            </button>
          )}
        </span>
      ) : resolving ? (
        <span className={s.note}>{t("statusBar.resolving")}</span>
      ) : effective === undefined ? (
        <span className={s.note}>{t("statusBar.unresolved")}</span>
      ) : null}
    </div>
  );
}
