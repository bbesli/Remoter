/**
 * The window footer: counts and the auto-lock countdown.
 *
 * The countdown ticks locally between refreshes of `vault_state` rather than
 * polling the core once a second. The core stays authoritative — every
 * refetch resets the local clock to whatever it reports — but a second of IPC
 * chatter to move a number is not worth the wake-ups.
 */

import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";

import { useSessions } from "@/features/sessions";
import { ipc, type VaultState } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import s from "./Footer.module.css";

const TEXT = {
  sessions: "sessions",
  tunnels: "tunnels",
  openPanels: "Open the sessions and tunnels panel",
  locksIn: "vault locks in",
  noAutoLock: "auto-lock is off",
  connections: "connections",
  credentials: "credentials",
} as const;

/** Seconds below which the countdown reads as a warning rather than a fact. */
const WARN_AT_SECONDS = 60;

/** How often the tunnel count is refreshed. Slower than the panel's own poll. */
const TUNNEL_POLL_MS = 10_000;

interface FooterProps {
  vault: VaultState | undefined;
  /** Opens the sessions and tunnels panel. The counts are the way in. */
  onShowPanels: () => void;
}

function formatCountdown(seconds: number): string {
  const clamped = Math.max(0, Math.floor(seconds));
  const minutes = Math.floor(clamped / 60);
  const rest = clamped % 60;
  return `${String(minutes).padStart(2, "0")}:${String(rest).padStart(2, "0")}`;
}

export function Footer({ vault, onShowPanels }: FooterProps) {
  const sessionCount = useSessions((st) => st.order.length);

  // The tunnels are the core's, not the interface's: a forward opened in an
  // earlier run of this window is still running, and the footer has to count
  // it. Only asked for while the vault is open, since the command needs one.
  const tunnelsQuery = useQuery({
    queryKey: qk.tunnels(),
    queryFn: () => ipc.listTunnels(),
    enabled: vault?.unlocked === true,
    refetchInterval: TUNNEL_POLL_MS,
  });
  const tunnelCount = tunnelsQuery.data?.length ?? 0;

  const reported = vault?.locksInSeconds ?? null;
  const [remaining, setRemaining] = useState<number | null>(reported);

  useEffect(() => {
    setRemaining(reported);
  }, [reported]);

  useEffect(() => {
    if (reported === null) return;
    const id = window.setInterval(() => {
      setRemaining((prev) => (prev === null ? null : Math.max(0, prev - 1)));
    }, 1000);
    return () => window.clearInterval(id);
  }, [reported]);

  const warning = remaining !== null && remaining <= WARN_AT_SECONDS;

  return (
    <footer className={s.footer}>
      {/* The counts are the way into the panel that lists them. A number the
          user can see but not act on is a number they have to go looking for. */}
      <button
        type="button"
        className={s.link}
        onClick={onShowPanels}
        title={TEXT.openPanels}
        aria-label={TEXT.openPanels}
      >
        <span className={s.count}>{sessionCount}</span> {TEXT.sessions}
        <span className={s.sep} aria-hidden="true">
          ·
        </span>
        <span className={s.count}>{tunnelCount}</span> {TEXT.tunnels}
      </button>

      <div className={s.spacer} />

      {vault !== undefined && vault.unlocked && (
        <>
          <span>
            <span className={s.count}>{vault.connectionCount}</span> {TEXT.connections}
          </span>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span>
            <span className={s.count}>{vault.credentialCount}</span> {TEXT.credentials}
          </span>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
        </>
      )}

      {remaining === null ? (
        <span className={s.note}>{TEXT.noAutoLock}</span>
      ) : (
        <span>
          {TEXT.locksIn}{" "}
          <span className={warning ? s.countdownWarning : s.count}>
            {formatCountdown(remaining)}
          </span>
        </span>
      )}
    </footer>
  );
}
