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
import { formatClock, useLocale, useT } from "@/i18n";
import { ipc, type VaultState } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import s from "./Footer.module.css";

/** Seconds below which the countdown reads as a warning rather than a fact. */
const WARN_AT_SECONDS = 60;

/** How often the tunnel count is refreshed. Slower than the panel's own poll. */
const TUNNEL_POLL_MS = 10_000;

interface FooterProps {
  vault: VaultState | undefined;
  /** Opens the sessions and tunnels panel. The counts are the way in. */
  onShowPanels: () => void;
}

export function Footer({ vault, onShowPanels }: FooterProps) {
  const t = useT("shell");
  const { code: locale } = useLocale();
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
      {/* The number and its noun are one phrase, not a styled number with a
          label glued on: Russian inflects the noun on the number and Arabic
          has six forms of it, so `{count} {label}` is ungrammatical in half
          the shipping languages. The emphasis moved from the digit to the
          phrase — see the `.count` rule in Footer.module.css. */}
      <button
        type="button"
        className={s.link}
        onClick={onShowPanels}
        title={t("footer.openPanels")}
        aria-label={t("footer.openPanels")}
      >
        <span className={s.count}>{t("footer.sessions", { count: sessionCount })}</span>
        <span className={s.sep} aria-hidden="true">
          ·
        </span>
        <span className={s.count}>{t("footer.tunnels", { count: tunnelCount })}</span>
      </button>

      <div className={s.spacer} />

      {vault !== undefined && vault.unlocked && (
        <>
          <span className={s.count}>
            {t("footer.connections", { count: vault.connectionCount })}
          </span>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
          <span className={s.count}>
            {t("footer.credentials", { count: vault.credentialCount })}
          </span>
          <span className={s.sep} aria-hidden="true">
            ·
          </span>
        </>
      )}

      {/*
        Three states, not two.

        `locksInSeconds` is null in two quite different situations — auto-lock
        is switched off, and the vault is LOCKED — and this corner used to
        collapse them into one sentence. So the moment a vault locked itself
        after fifteen idle minutes, the footer announced that auto-lock was
        off: the one message contradicted by the thing that had just happened.
        A locked vault gets its own words, and a state not yet known gets
        none.
      */}
      {vault === undefined ? null : !vault.unlocked ? (
        <span className={s.note}>{t("footer.vaultLocked")}</span>
      ) : remaining === null ? (
        <span className={s.note}>{t("footer.noAutoLock")}</span>
      ) : (
        // The clock is inside the sentence rather than beside it, because
        // "vault locks in 04:31" does not put its number last in every
        // language. The warning tone moves to the whole phrase.
        <span className={warning ? s.countdownWarning : undefined}>
          {t("footer.locksIn", { clock: formatClock(locale, remaining) })}
        </span>
      )}
    </footer>
  );
}
