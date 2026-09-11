/**
 * Everything open, in one place: sessions and tunnels.
 *
 * Design 06. Two panes, because they answer different questions — "what is
 * running and how is it behaving" and "what ports are open on this machine" —
 * and the second one is a security question the user should be able to ask
 * without opening a session first.
 *
 * Three details from the design are load-bearing rather than decorative:
 *
 * - **Route is a column, not a tooltip.** When a session goes through two
 *   bastions, that is the first thing worth knowing when it goes slow.
 * - **Exposed forwards are loud.** A forward bound beyond loopback opens a path
 *   into this machine from the network. It gets a red row, a red address and a
 *   labelled badge — three signals, not one colour.
 * - **A bind failure says which port.** The core's message already does; it is
 *   shown whole rather than replaced with "could not open tunnel".
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import clsx from "clsx";

import { Badge } from "@/components/Badge";
import { BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { asFailure, ipc, type ForwardDirection, type Tunnel } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";
import { formatNumber, isolate, isolateChain, isolateLtr, useLocale, useT } from "@/i18n";

import { AddForwardDialog } from "./AddForwardDialog";
import { requestCloseTab } from "./closing";
import { formatBytes, formatSize, formatUptime } from "./format";
import { describeRenderer } from "./renderer";
import { useSessions } from "./store";

import s from "./SessionPanels.module.css";

/**
 * Which way each forward points, for the badge on its row.
 *
 * A record and not a key built from the value: a direction the core adds
 * without a word for it should stop the build rather than reach a badge.
 */
const DIRECTION_KEYS = {
  local: "panels.direction.local",
  remote: "panels.direction.remote",
  dynamic: "panels.direction.dynamic",
} as const satisfies Record<ForwardDirection, string>;

/**
 * The cell for a value that is not there — no echo sample yet, no size, no
 * protocol. An em dash is punctuation, not copy, and is the same in every
 * language this ships in.
 */
const NO_VALUE = "—";

/** How often the tunnel counters are refreshed while the panel is open. */
const TUNNEL_POLL_MS = 2000;

function TunnelRow({
  tunnel,
  onClose,
  closing,
}: {
  tunnel: Tunnel;
  onClose: () => void;
  closing: boolean;
}) {
  const t = useT("sessions");
  const { code: locale } = useLocale();

  const exposed = tunnel.exposure === "network";
  // A bind address is left-to-right by specification whatever characters it
  // holds, and the port the server chose is interpolated rather than glued on:
  // a language that brackets differently should be able to say so.
  const listening = isolateLtr(
    tunnel.listening ??
      (tunnel.direction === "remote" && tunnel.remotePort !== null
        ? t("panels.remoteBind", { bind: tunnel.bind, port: String(tunnel.remotePort) })
        : tunnel.bind),
  );
  const closeForward = t("panels.closeForward");

  return (
    <tr className={clsx(s.row, exposed && s.rowExposed)}>
      <td className={s.cell}>
        <Badge tone={exposed ? "danger" : "neutral"}>{t(DIRECTION_KEYS[tunnel.direction])}</Badge>
      </td>
      <td className={s.cell}>
        <span className={clsx(s.mono, exposed && s.monoExposed)}>{listening}</span>
        <span className={s.arrow} aria-hidden="true">
          {" → "}
        </span>
        <span className={s.mono}>
          {tunnel.destination === null ? t("panels.socks") : isolateLtr(tunnel.destination)}
        </span>
        {exposed && (
          <span className={s.exposedNote}>
            <Icon name="alert" size={12} />
            {t("panels.exposed")}
          </span>
        )}
        {tunnel.direction === "remote" && tunnel.listening === null && (
          <span className={s.subtle}>{t("panels.serverListener")}</span>
        )}
      </td>
      <td className={s.cell}>{isolate(tunnel.name)}</td>
      <td className={s.cell}>
        <span className={s.mono}>
          {tunnel.running ? formatBytes(locale, tunnel.bytes) : t("panels.stopped")}
        </span>
      </td>
      <td className={s.cell}>
        <span className={s.mono}>
          {tunnel.active === 0 ? t("panels.inactive") : formatNumber(locale, tunnel.active)}
        </span>
      </td>
      <td className={clsx(s.cell, s.cellActions)}>
        <Button
          variant="ghost"
          size="sm"
          onClick={onClose}
          disabled={closing}
          ariaLabel={closeForward}
          title={closeForward}
        >
          <Icon name="x" size={13} />
        </Button>
      </td>
    </tr>
  );
}

export function SessionPanels({ onClose }: { onClose: () => void }) {
  const t = useT("sessions");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const [pane, setPane] = useState<"sessions" | "tunnels">("sessions");
  const [adding, setAdding] = useState(false);
  // The uptime column ticks. Held as state so the render stays pure.
  const [now, setNow] = useState(Date.now);
  const panelRef = useRef<HTMLDivElement>(null);
  const queryClient = useQueryClient();

  const order = useSessions((st) => st.order);
  const byId = useSessions((st) => st.byId);
  const activate = useSessions((st) => st.activate);

  useFocusTrap(true, panelRef);
  useModalRegistration("session-panels", true);

  useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, []);

  // Escape closes the panel, and the press is swallowed so the shell behind
  // does not also act on it. The nested add-forward dialog registers its own
  // handler and stops propagation first, so it wins while it is open.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopPropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [onClose]);

  const tunnelsQuery = useQuery({
    queryKey: qk.tunnels(),
    queryFn: () => ipc.listTunnels(),
    // Counters are live, so the panel refreshes while it is open and stops the
    // moment it closes — a background poll for a panel nobody is looking at is
    // wake-ups spent on nothing.
    refetchInterval: TUNNEL_POLL_MS,
  });

  const closeTunnel = useMutation({
    mutationFn: (tunnelId: number) => ipc.closeTunnel(tunnelId),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.tunnels() }),
  });

  const records = useMemo(
    () => order.map((id) => byId[id]).filter((r) => r !== undefined),
    [order, byId],
  );

  const tunnels = tunnelsQuery.data ?? [];
  const tunnelFailure =
    tunnelsQuery.error !== null && tunnelsQuery.error !== undefined
      ? asFailure(tunnelsQuery.error)
      : null;
  const closeFailure = closeTunnel.error === null ? null : asFailure(closeTunnel.error);

  /** The node a new forward defaults to: whichever session is in front. */
  const defaultNode = records.find((r) => r.phase === "running") ?? records[0];

  const close = tCommon("action.close");
  const echoNote = t("panels.echoNote");

  return (
    <div className={s.backdrop}>
      <div
        ref={panelRef}
        className={s.panel}
        role="dialog"
        aria-modal="true"
        aria-label={t("panels.label")}
        tabIndex={-1}
      >
        {/* A header of the interface's own, so it reserves the width the
            frameless window's controls sit in. */}
        <header className={s.header}>
          <div className={s.paneTabs}>
            <button
              type="button"
              className={clsx(s.paneTab, pane === "sessions" && s.paneTabOn)}
              onClick={() => setPane("sessions")}
              aria-pressed={pane === "sessions"}
            >
              {t("panels.sessions")}
              <span className={s.paneCount}>{formatNumber(locale, records.length)}</span>
            </button>
            <button
              type="button"
              className={clsx(s.paneTab, pane === "tunnels" && s.paneTabOn)}
              onClick={() => setPane("tunnels")}
              aria-pressed={pane === "tunnels"}
            >
              {t("panels.tunnels")}
              <span className={s.paneCount}>{formatNumber(locale, tunnels.length)}</span>
            </button>
          </div>
          <div className={s.headerSpacer} />
          <button
            type="button"
            className={s.closeButton}
            onClick={onClose}
            aria-label={close}
            title={close}
          >
            <Icon name="x" size={14} />
          </button>
        </header>

        <div className={s.body}>
          {pane === "sessions" ? (
            records.length === 0 ? (
              <p className={s.empty}>{t("panels.noSessions")}</p>
            ) : (
              <div className={s.tableScroll}>
                <table className={s.table}>
                  <thead>
                    <tr>
                      <th className={s.head}>{t("panels.column.session")}</th>
                      <th className={s.head}>{t("panels.column.protocol")}</th>
                      <th className={s.head}>{t("panels.column.uptime")}</th>
                      <th className={s.head} title={echoNote}>
                        {t("panels.column.echo")}
                      </th>
                      <th className={s.head}>{t("panels.column.transferred")}</th>
                      <th className={s.head}>{t("panels.column.size")}</th>
                      <th className={s.head}>{t("panels.column.route")}</th>
                      <th className={s.head}>{t("panels.column.renderer")}</th>
                      <th className={s.head} />
                    </tr>
                  </thead>
                  <tbody>
                    {records.map((record) => {
                      const via = record.opened?.via ?? [];
                      const started = record.opened?.startedAtMs ?? record.startedAt;
                      return (
                        <tr key={record.tabId} className={s.row}>
                          <td className={s.cell}>
                            {/* Vault data and a machine address: isolated so a
                                right-to-left character in either cannot
                                reorder the cell around it. */}
                            <span className={s.sessionName}>{isolate(record.name)}</span>
                            <span className={s.subtle}>
                              {record.target === null ? "" : isolateLtr(record.target)}
                            </span>
                          </td>
                          <td className={s.cell}>
                            {/* A protocol name — SSH, RDP, VNC, SFTP — is never
                                translated (docs/features/i18n.md). */}
                            <Badge tone="accent">
                              {record.opened?.protocol ?? record.protocol ?? NO_VALUE}
                            </Badge>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {record.phase === "running"
                                ? formatUptime(t, locale, now - started)
                                : NO_VALUE}
                            </span>
                          </td>
                          <td className={s.cell} title={echoNote}>
                            <span className={s.mono}>
                              {record.metrics.echoMs === null
                                ? NO_VALUE
                                : t("panels.echoValue", { milliseconds: record.metrics.echoMs })}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {t("status.transfer", {
                                in: formatBytes(locale, record.metrics.bytesIn),
                                out: formatBytes(locale, record.metrics.bytesOut),
                              })}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {record.metrics.cols === 0
                                ? NO_VALUE
                                : formatSize(locale, record.metrics.cols, record.metrics.rows)}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {via.length === 0
                                ? t("panels.direct")
                                : isolateChain(via, tCommon("punctuation.chainSeparator"))}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.subtle}>{describeRenderer(t, record.renderer)}</span>
                          </td>
                          <td className={clsx(s.cell, s.cellActions)}>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                activate(record.tabId);
                                onClose();
                              }}
                            >
                              {t("panels.focus")}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                // The panel goes first, then the question. Two
                                // focus traps on screen at once is the defect
                                // `useModalRegistration` was added for, and
                                // this panel registers one of its own — so it
                                // stands down rather than stacking under the
                                // confirmation it opened.
                                onClose();
                                requestCloseTab(record.tabId);
                              }}
                            >
                              {t("panels.disconnect")}
                            </Button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )
          ) : (
            <>
              {tunnelFailure !== null && (
                <div className={s.notice}>
                  <FailureNotice
                    failure={tunnelFailure}
                    title={t("panels.tunnelsFailed")}
                    onRetry={() => void tunnelsQuery.refetch()}
                    retryLabel={tCommon("action.retry")}
                  />
                </div>
              )}
              {closeFailure !== null && (
                <div className={s.notice}>
                  <FailureNotice failure={closeFailure} title={t("panels.closeFailed")} />
                </div>
              )}
              {tunnelsQuery.isPending ? (
                <div className={s.notice}>
                  <BusyStatus label={t("panels.loadingTunnels")} size={16} />
                </div>
              ) : tunnels.length === 0 ? (
                <p className={s.empty}>{t("panels.noTunnels")}</p>
              ) : (
                <div className={s.tableScroll}>
                  <table className={s.table}>
                    <thead>
                      <tr>
                        <th className={s.head}>{t("panels.column.type")}</th>
                        <th className={s.head}>{t("panels.column.forward")}</th>
                        <th className={s.head}>{t("panels.column.via")}</th>
                        <th className={s.head}>{t("panels.column.traffic")}</th>
                        <th className={s.head}>{t("panels.column.connections")}</th>
                        <th className={s.head} />
                      </tr>
                    </thead>
                    <tbody>
                      {tunnels.map((tunnel) => (
                        <TunnelRow
                          key={tunnel.tunnelId}
                          tunnel={tunnel}
                          closing={closeTunnel.isPending}
                          onClose={() => closeTunnel.mutate(tunnel.tunnelId)}
                        />
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </>
          )}
        </div>

        <footer className={s.footer}>
          {pane === "tunnels" ? (
            <>
              <Button variant="secondary" size="sm" onClick={() => setAdding(true)}>
                <Icon name="plus" size={13} />
                {t("panels.addForward")}
              </Button>
              <span className={s.footerNote}>{t("panels.bindNote")}</span>
            </>
          ) : (
            <span className={s.footerNote}>
              {t("panels.openCount", { count: records.length })}
            </span>
          )}
        </footer>
      </div>

      {adding && (
        <AddForwardDialog
          defaultNodeId={defaultNode?.nodeId ?? null}
          onClose={() => setAdding(false)}
          onOpened={() => {
            setAdding(false);
            void queryClient.invalidateQueries({ queryKey: qk.tunnels() });
          }}
        />
      )}
    </div>
  );
}
