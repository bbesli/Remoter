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
import { asFailure, ipc, type Tunnel } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useFocusTrap } from "@/features/connections/focusTrap";
import { useModalRegistration } from "@/hooks/useModalRegistration";

import { AddForwardDialog } from "./AddForwardDialog";
import { closeTab } from "./manager";
import { formatBytes, formatSize, formatUptime } from "./format";
import { describeRenderer } from "./renderer";
import { useSessions } from "./store";

import s from "./SessionPanels.module.css";

const TEXT = {
  label: "Sessions and tunnels",
  sessions: "Sessions",
  tunnels: "Tunnels",
  close: "Close",

  colSession: "Session",
  colProtocol: "Protocol",
  colUptime: "Uptime",
  colEcho: "Echo",
  colTransferred: "Transferred",
  colRoute: "Route",
  colRenderer: "Renderer",
  colSize: "Size",

  colType: "Type",
  colForward: "Forward",
  colVia: "Via",
  colTraffic: "Traffic",
  colConns: "Conns",

  direct: "direct",
  noSessions: "Nothing is open. Double-click a connection in the tree to start one.",
  noTunnels: "No forwards are running.",
  focus: "Focus tab",
  disconnect: "Disconnect",
  closeForward: "Close this forward",
  addForward: "Add forward",
  bindNote: "New forwards bind to 127.0.0.1 unless you change it.",
  exposed: "exposed to the network",
  socks: "SOCKS5 proxy",
  inactive: "inactive",
  stopped: "not running",
  loadingTunnels: "Reading the running forwards…",
  tunnelsFailed: "The forwards could not be read",
  closeFailed: "The forward was not closed",
  retry: "Try again",
  openCount: (n: number) => `${String(n)} open`,
  echoNote: "Time from the last keystroke to the next frame of output.",
  noEcho: "—",
  serverListener: "listener is on the server",
} as const;

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
  const exposed = tunnel.exposure === "network";
  const listening =
    tunnel.listening ??
    (tunnel.direction === "remote"
      ? tunnel.remotePort === null
        ? tunnel.bind
        : `${tunnel.bind} (port ${String(tunnel.remotePort)})`
      : tunnel.bind);

  return (
    <tr className={clsx(s.row, exposed && s.rowExposed)}>
      <td className={s.cell}>
        <Badge tone={exposed ? "danger" : "neutral"}>{tunnel.direction}</Badge>
      </td>
      <td className={s.cell}>
        <span className={clsx(s.mono, exposed && s.monoExposed)}>{listening}</span>
        <span className={s.arrow} aria-hidden="true">
          {" → "}
        </span>
        <span className={s.mono}>{tunnel.destination ?? TEXT.socks}</span>
        {exposed && (
          <span className={s.exposedNote}>
            <Icon name="alert" size={12} />
            {TEXT.exposed}
          </span>
        )}
        {tunnel.direction === "remote" && tunnel.listening === null && (
          <span className={s.subtle}>{TEXT.serverListener}</span>
        )}
      </td>
      <td className={s.cell}>{tunnel.name}</td>
      <td className={s.cell}>
        <span className={s.mono}>
          {tunnel.running ? formatBytes(tunnel.bytes) : TEXT.stopped}
        </span>
      </td>
      <td className={s.cell}>
        <span className={s.mono}>
          {tunnel.active === 0 ? TEXT.inactive : String(tunnel.active)}
        </span>
      </td>
      <td className={clsx(s.cell, s.cellActions)}>
        <Button
          variant="ghost"
          size="sm"
          onClick={onClose}
          disabled={closing}
          ariaLabel={TEXT.closeForward}
          title={TEXT.closeForward}
        >
          <Icon name="x" size={13} />
        </Button>
      </td>
    </tr>
  );
}

export function SessionPanels({ onClose }: { onClose: () => void }) {
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

  return (
    <div className={s.backdrop}>
      <div
        ref={panelRef}
        className={s.panel}
        role="dialog"
        aria-modal="true"
        aria-label={TEXT.label}
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
              {TEXT.sessions}
              <span className={s.paneCount}>{records.length}</span>
            </button>
            <button
              type="button"
              className={clsx(s.paneTab, pane === "tunnels" && s.paneTabOn)}
              onClick={() => setPane("tunnels")}
              aria-pressed={pane === "tunnels"}
            >
              {TEXT.tunnels}
              <span className={s.paneCount}>{tunnels.length}</span>
            </button>
          </div>
          <div className={s.headerSpacer} />
          <button
            type="button"
            className={s.closeButton}
            onClick={onClose}
            aria-label={TEXT.close}
            title={TEXT.close}
          >
            <Icon name="x" size={14} />
          </button>
        </header>

        <div className={s.body}>
          {pane === "sessions" ? (
            records.length === 0 ? (
              <p className={s.empty}>{TEXT.noSessions}</p>
            ) : (
              <div className={s.tableScroll}>
                <table className={s.table}>
                  <thead>
                    <tr>
                      <th className={s.head}>{TEXT.colSession}</th>
                      <th className={s.head}>{TEXT.colProtocol}</th>
                      <th className={s.head}>{TEXT.colUptime}</th>
                      <th className={s.head} title={TEXT.echoNote}>
                        {TEXT.colEcho}
                      </th>
                      <th className={s.head}>{TEXT.colTransferred}</th>
                      <th className={s.head}>{TEXT.colSize}</th>
                      <th className={s.head}>{TEXT.colRoute}</th>
                      <th className={s.head}>{TEXT.colRenderer}</th>
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
                            <span className={s.sessionName}>{record.name}</span>
                            <span className={s.subtle}>{record.target ?? ""}</span>
                          </td>
                          <td className={s.cell}>
                            <Badge tone="accent">{record.opened?.protocol ?? record.protocol ?? "—"}</Badge>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {record.phase === "running" ? formatUptime(now - started) : "—"}
                            </span>
                          </td>
                          <td className={s.cell} title={TEXT.echoNote}>
                            <span className={s.mono}>
                              {record.metrics.echoMs === null
                                ? TEXT.noEcho
                                : `${String(record.metrics.echoMs)} ms`}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              ↓{formatBytes(record.metrics.bytesIn)} ↑
                              {formatBytes(record.metrics.bytesOut)}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {record.metrics.cols === 0
                                ? "—"
                                : formatSize(record.metrics.cols, record.metrics.rows)}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.mono}>
                              {via.length === 0 ? TEXT.direct : via.join(" → ")}
                            </span>
                          </td>
                          <td className={s.cell}>
                            <span className={s.subtle}>{describeRenderer(record.renderer)}</span>
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
                              {TEXT.focus}
                            </Button>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => void closeTab(record.tabId)}
                            >
                              {TEXT.disconnect}
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
                    title={TEXT.tunnelsFailed}
                    onRetry={() => void tunnelsQuery.refetch()}
                    retryLabel={TEXT.retry}
                  />
                </div>
              )}
              {closeFailure !== null && (
                <div className={s.notice}>
                  <FailureNotice failure={closeFailure} title={TEXT.closeFailed} />
                </div>
              )}
              {tunnelsQuery.isPending ? (
                <div className={s.notice}>
                  <BusyStatus label={TEXT.loadingTunnels} size={16} />
                </div>
              ) : tunnels.length === 0 ? (
                <p className={s.empty}>{TEXT.noTunnels}</p>
              ) : (
                <div className={s.tableScroll}>
                  <table className={s.table}>
                    <thead>
                      <tr>
                        <th className={s.head}>{TEXT.colType}</th>
                        <th className={s.head}>{TEXT.colForward}</th>
                        <th className={s.head}>{TEXT.colVia}</th>
                        <th className={s.head}>{TEXT.colTraffic}</th>
                        <th className={s.head}>{TEXT.colConns}</th>
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
                {TEXT.addForward}
              </Button>
              <span className={s.footerNote}>{TEXT.bindNote}</span>
            </>
          ) : (
            <span className={s.footerNote}>{TEXT.openCount(records.length)}</span>
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
