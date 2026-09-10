/**
 * Update checking.
 *
 * It checks. It does not install. Those are two features and only one of them
 * is here, so the screen says which — in one line, next to the button, not in
 * a document nobody installing a binary will read. Tauri's updater installs a
 * downloaded artefact, and installing an artefact means trusting its
 * signature; releases are not signed yet
 * (`docs/development/build-release.md`). Shipping self-update first would mean
 * a credential manager downloading and running an unsigned binary, which is
 * the one thing this application exists not to do.
 *
 * Three rules shaped the rest of it:
 *
 * 1. **Off until asked for.** The switch writes `updateCheckEnabled`, which
 *    the core stores and starts at `false`. Nothing is contacted while it is
 *    off, and the sentence above the switch says exactly what is sent when it
 *    is on — a version string — because a consent line that is vague is not
 *    consent.
 * 2. **"Check now" works either way.** It is the user asking directly, which
 *    is a different thing from standing permission, so it does not need the
 *    switch. That is also what makes the feature usable by somebody who never
 *    wants an automatic check.
 * 3. **Every failure gets its own sentence.** Offline, rate-limited, no
 *    release list, unreadable answer — the core distinguishes them and this
 *    shows the distinction. A check that fails vaguely teaches people to stop
 *    believing it, which is worse than not having one.
 *
 * What the switch does *not* do is check at application start: nothing in the
 * shell calls this yet, and the label says so rather than implying otherwise.
 * The line under it is the honest description of today's behaviour — once when
 * permission is given, and after that at most once a day when this screen is
 * opened. Turning it on runs a check immediately on purpose: the user has just
 * consented, and a switch that produces no visible effect is a switch nobody
 * can tell is working.
 *
 * Release notes are remote text a release author wrote. They render as text.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { openUrl } from "@tauri-apps/plugin-opener";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Spinner } from "@/components/Spinner";
import { asFailure, ipc } from "@/lib/ipc";
import type { AppSettings, IpcFailure, UpdateCheck } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";

import { SettingsSection } from "./SettingsSection";
import { pickUpdate } from "./version";
import s from "./UpdatesSection.module.css";

const TEXT = {
  title: "Updates",
  description:
    "Remoter can look for a newer release. It does not install one, and it contacts nothing unless you ask it to.",

  switchLabel: "Look for a newer release automatically",
  switchOn: "On",
  switchOff: "Off",
  consent:
    "With this on, Remoter contacts github.com at most once a day — once when you turn it on, and after that when you open this screen — and sends one thing: this build's version string. No identifier, no locale, no telemetry, no usage data. With it off, nothing is contacted until you press Check now.",
  switchSaving: "Saving…",
  switchFailed: "That preference was not saved.",
  switchRetry: "Save again",

  checkNow: "Check now",
  checking: "Asking GitHub what has been released…",
  lastCheckedNever: "This machine has never checked.",
  lastChecked: (when: string) => `Last checked ${when}.`,

  checkFailed: "The update check did not finish.",
  checkRetry: "Try again",

  current: (version: string) => `You are running ${version}, and it is the newest release.`,
  none: (version: string) =>
    `No release has been published yet. You are running ${version}.`,
  unknown: (version: string) =>
    `This build reports its version as ${version}, which is not a version that can be compared. Open the releases page and check by eye.`,

  updateHeading: (version: string) => `Version ${version} is available`,
  updateRunning: (version: string) => `You are running ${version}.`,
  published: (when: string) => `Published ${when}.`,
  notesHeading: "What changed",
  notesNone: "This release was published without notes.",
  openRelease: "Open the release page",
  openReleases: "Open the releases page",

  noSelfUpdate:
    "Remoter does not install updates itself. Releases are not signed yet, and running an unsigned binary is not something a credential manager should ask you to do — so the button opens the release page in your browser and you install it yourself.",

  openFailed: "The system browser did not open.",

  promiseTitle: "Remoter does not phone home",
  promises: [
    "No telemetry. No usage reporting. No analytics of any kind, at any setting.",
    "No crash upload. A crash report is written to your machine and you decide whether to attach it to an issue — which means you can read it first, and that matters when the process holds credentials.",
    "The update check is the only request Remoter makes that is not a session you opened. It reads the public release list and sends this build's version. It downloads nothing.",
  ],
} as const;

/** Where the browser goes when there is no one release to point at. */
const RELEASES_URL = "https://github.com/bbesli/Remoter/releases";

/**
 * A day between automatic checks.
 *
 * Long enough that opening settings four times in an afternoon makes one
 * request, short enough that a release published this week is found this week.
 */
const CHECK_INTERVAL_SECONDS = 24 * 60 * 60;

const STAMP = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });
const DAY = new Intl.DateTimeFormat(undefined, { dateStyle: "medium" });

const CONSENT_ID = "settings-updates-consent";

/** Formats an RFC 3339 stamp, or gives nothing back if it is not one. */
function publishedOn(rfc3339: string | null): string | null {
  if (rfc3339 === null || rfc3339 === "") return null;
  const at = new Date(rfc3339);
  return Number.isNaN(at.getTime()) ? null : DAY.format(at);
}

export function UpdatesSection() {
  const queryClient = useQueryClient();
  const [openFailure, setOpenFailure] = useState<IpcFailure | null>(null);

  // The builder, and the same cache entry the settings screen reads and
  // writes — so a toggle here and a theme change there do not fight over two
  // copies of the settings.
  const settings = useQuery({
    queryKey: qk.settings(),
    queryFn: ipc.getSettings,
  });

  const check = useMutation<UpdateCheck, unknown, void>({
    mutationFn: () => ipc.checkForUpdate(),
    onSuccess: () => {
      // The core recorded the time in the settings file; re-read it rather
      // than assume, so "last checked" says what was actually stored.
      void queryClient.invalidateQueries({ queryKey: qk.settings() });
    },
  });

  const runCheck = check.mutate;
  const attempted = useRef(false);

  const consent = useMutation<AppSettings, unknown, boolean>({
    mutationFn: (enabled) => ipc.setSettings({ updateCheckEnabled: enabled }),
    onSuccess: (next, enabled) => {
      queryClient.setQueryData(qk.settings(), next);
      if (!enabled) return;

      // The sentence beside the switch promises a check "once when you turn it
      // on", and it is the switch's only visible effect — so it happens here,
      // where consent was actually given, rather than being left to the effect
      // below. That effect answers a different question ("is this visit due a
      // check?") and its once-a-day guard would swallow this one for anybody
      // who had pressed Check now, or had the switch on earlier the same day.
      // Marked as attempted so the effect does not then add a second request
      // when the stored settings come back changed.
      attempted.current = true;
      runCheck();
    },
  });

  const loaded = settings.data;
  const enabled = loaded?.updateCheckEnabled ?? false;
  const lastCheckedAt = loaded?.updateLastCheckedAt ?? null;

  // Opening this screen with the switch already on, which is the other half of
  // what the consent sentence describes: once per mount, only with permission,
  // and only when the stored stamp is old enough. The ref is what stops a
  // refetch of the settings from turning one visit into several requests.
  // Turning the switch on is handled where the switch is, above.
  useEffect(() => {
    if (attempted.current) return;
    if (loaded === undefined || !loaded.updateCheckEnabled) return;

    const last = loaded.updateLastCheckedAt;
    const due = last === null || Date.now() / 1000 - last >= CHECK_INTERVAL_SECONDS;
    if (!due) return;

    attempted.current = true;
    runCheck();
  }, [loaded, runCheck]);

  async function open(url: string) {
    setOpenFailure(null);
    try {
      await openUrl(url);
    } catch (e) {
      setOpenFailure(asFailure(e));
    }
  }

  const found = check.data;
  const verdict = found === undefined ? null : pickUpdate(found.currentVersion, found.releases);
  const release = verdict !== null && verdict.kind === "update" ? verdict.release : null;
  const published = release === null ? null : publishedOn(release.publishedAt);

  return (
    <SettingsSection title={TEXT.title} description={TEXT.description}>
      <div className={s.control}>
        <label className={s.switchRow}>
          <input
            className={s.checkbox}
            type="checkbox"
            role="switch"
            checked={enabled}
            disabled={loaded === undefined || consent.isPending}
            onChange={(event) => consent.mutate(event.target.checked)}
            aria-describedby={CONSENT_ID}
          />
          <span className={s.track} aria-hidden="true">
            <span className={s.thumb} />
          </span>
          <span className={s.switchLabel}>{TEXT.switchLabel}</span>
          {/* The word, not only the switch position — state is never colour or
              shape alone. */}
          <span className={s.state}>
            {consent.isPending ? TEXT.switchSaving : enabled ? TEXT.switchOn : TEXT.switchOff}
          </span>
        </label>

        <p className={s.consent} id={CONSENT_ID}>
          {TEXT.consent}
        </p>

        {consent.isError && (
          <FailureNotice
            failure={asFailure(consent.error)}
            title={TEXT.switchFailed}
            onRetry={() => consent.mutate(!enabled)}
            retryLabel={TEXT.switchRetry}
          />
        )}
      </div>

      <div className={s.control}>
        <div className={s.actions}>
          <Button variant="secondary" size="sm" onClick={() => runCheck()} disabled={check.isPending}>
            {TEXT.checkNow}
          </Button>
          <span className={s.stamp}>
            {lastCheckedAt === null
              ? TEXT.lastCheckedNever
              : TEXT.lastChecked(STAMP.format(new Date(lastCheckedAt * 1000)))}
          </span>
        </div>

        {/* Polite rather than assertive: the result is worth reading, not worth
            interrupting whatever the screen reader is already saying. */}
        <div className={s.result} aria-live="polite">
          {check.isPending && (
            <p className={s.waiting}>
              <Spinner size={16} label={TEXT.checking} />
              {TEXT.checking}
            </p>
          )}

          {check.isError && (
            <FailureNotice
              failure={asFailure(check.error)}
              title={TEXT.checkFailed}
              onRetry={() => runCheck()}
              retryLabel={TEXT.checkRetry}
            >
              <Button size="sm" variant="ghost" onClick={() => void open(RELEASES_URL)}>
                {TEXT.openReleases}
              </Button>
            </FailureNotice>
          )}

          {!check.isPending && verdict !== null && verdict.kind === "current" && (
            <p className={s.verdict}>{TEXT.current(verdict.version)}</p>
          )}

          {!check.isPending && verdict !== null && verdict.kind === "none" && (
            <p className={s.verdict}>{TEXT.none(verdict.version)}</p>
          )}

          {!check.isPending && verdict !== null && verdict.kind === "unknown" && (
            <div className={s.verdictWithAction}>
              <p className={s.verdict}>{TEXT.unknown(verdict.version)}</p>
              <Button size="sm" onClick={() => void open(RELEASES_URL)}>
                {TEXT.openReleases}
              </Button>
            </div>
          )}

          {!check.isPending && verdict !== null && verdict.kind === "update" && release !== null && (
            <div className={s.release}>
              <div className={s.releaseHead}>
                <h3 className={s.releaseTitle}>{TEXT.updateHeading(verdict.version)}</h3>
                <p className={s.releaseMeta}>
                  {TEXT.updateRunning(found?.currentVersion ?? "")}
                  {published !== null && ` ${TEXT.published(published)}`}
                </p>
              </div>

              <div className={s.notes}>
                <p className={s.notesHeading}>{TEXT.notesHeading}</p>
                {/* Remote text, written by whoever published the release. It is
                    rendered as text — never as markup — and is selectable so it
                    can be copied into an issue. */}
                <pre className={["selectable", s.notesBody].join(" ")}>
                  {release.notes.trim() === "" ? TEXT.notesNone : release.notes}
                </pre>
              </div>

              <p className={s.noSelfUpdate}>{TEXT.noSelfUpdate}</p>

              <div className={s.releaseActions}>
                <Button variant="primary" size="sm" onClick={() => void open(release.url)}>
                  {TEXT.openRelease}
                </Button>
                {/* Shown as well as opened: a user whose desktop cannot launch a
                    browser from here can still copy it. */}
                <code className={["selectable", s.url].join(" ")}>{release.url}</code>
              </div>
            </div>
          )}

          {openFailure !== null && (
            <FailureNotice failure={openFailure} title={TEXT.openFailed} />
          )}
        </div>
      </div>

      <Callout tone="info" title={TEXT.promiseTitle}>
        <ul className={s.list}>
          {TEXT.promises.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ul>
      </Callout>
    </SettingsSection>
  );
}
