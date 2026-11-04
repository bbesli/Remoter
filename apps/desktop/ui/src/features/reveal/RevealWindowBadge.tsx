/**
 * The corner countdown: how long stored passwords are shown without asking
 * for the vault password again.
 *
 * Mounted once, at the shell, and drawn only while the window is open. The
 * per-second tick lives in {@link Countdown}, which is the only thing that
 * re-renders on it — the shell, the tree and the sessions behind it do not
 * hear about a clock they have no use for. Nothing polls the core: the end
 * time arrives with every answer the core gives, and the core is the one that
 * decides, so a countdown that is a second out costs a prompt at worst and
 * never skips one.
 *
 * On mount it asks the core once. The store's value may be left over from
 * before the vault locked; until the core has answered, nothing is drawn.
 */

import { useCallback, useEffect, useState } from "react";

import { Icon } from "@/components/Icon";
import { formatClock, useLocale, useT } from "@/i18n";
import { ipc } from "@/lib/ipc";
import { useApp } from "@/stores/app";

import s from "./RevealWindowBadge.module.css";

export function RevealWindowBadge() {
  const until = useApp((st) => st.revealUntil);
  const setUntil = useApp((st) => st.setRevealUntil);
  const [synced, setSynced] = useState(false);

  useEffect(() => {
    let cancelled = false;
    ipc.revealWindow().then(
      (answer) => {
        if (cancelled) return;
        setUntil(answer.remainingMs === null ? null : Date.now() + answer.remainingMs);
        setSynced(true);
      },
      () => {
        // A core that cannot answer has no window to show. The next password
        // shown asks, which is the safe way to be wrong.
        if (cancelled) return;
        setUntil(null);
        setSynced(true);
      },
    );
    return () => {
      cancelled = true;
    };
  }, [setUntil]);

  // Stable, so the countdown's timer is not torn down and rebuilt for a
  // render that changed nothing it depends on.
  const elapsed = useCallback(() => setUntil(null), [setUntil]);

  if (!synced || until === null) return null;
  return <Countdown until={until} onElapsed={elapsed} />;
}

interface CountdownProps {
  until: number;
  onElapsed: () => void;
}

function Countdown({ until, onElapsed }: CountdownProps) {
  const t = useT("connections");
  const { code: locale } = useLocale();
  const [now, setNow] = useState(() => Date.now());
  const [ending, setEnding] = useState(false);
  const remaining = Math.max(0, until - now);

  useEffect(() => {
    // Aligned to the next whole second of the deadline, so the digits change
    // when the second does rather than up to a second late.
    let timer = 0;
    const tick = () => {
      const current = Date.now();
      setNow(current);
      const left = until - current;
      if (left <= 0) {
        onElapsed();
        return;
      }
      timer = window.setTimeout(tick, (left % 1000) + 5);
    };
    timer = window.setTimeout(tick, ((until - Date.now()) % 1000) + 5);
    return () => window.clearTimeout(timer);
  }, [until, onElapsed]);

  const end = () => {
    setEnding(true);
    ipc.endRevealWindow().then(
      () => onElapsed(),
      () => setEnding(false),
    );
  };

  return (
    <section className={s.badge} aria-label={t("reveal.badgeTitle")}>
      <Icon name="unlock" size={14} />
      <span className={s.text}>
        <span className={s.title}>{t("reveal.badgeTitle")}</span>
        {/* Not a live region: a screen reader announcing every second is a
            screen reader that cannot be used for anything else. */}
        <span className={s.time} aria-live="off">
          {t("reveal.badgeRemaining", { time: formatClock(locale, remaining / 1000) })}
        </span>
      </span>
      <button
        type="button"
        className={s.end}
        onClick={end}
        disabled={ending}
        title={t("reveal.endNowHint")}
      >
        <Icon name="lock" size={12} />
        {t("reveal.endNow")}
      </button>
    </section>
  );
}
