/**
 * Unlocking a vault.
 *
 * The screen lists the slots this vault actually has — `vault_probe` reads the
 * cleartext header, so a vault with one password slot shows one row and no
 * invented alternatives.
 *
 * Two rules from docs/security/key-management.md are load-bearing here:
 *
 *  - A failed unlock says only "That did not unlock the vault." Naming the
 *    factor that was wrong tells an attacker which half they already have.
 *    The core enforces this by construction: `UnlockError::NotUnlocked` is the
 *    only variant mapped to `vault.unlock-failed`, and that one code is the
 *    only one this screen replaces with the fixed sentence. The message is
 *    flagged SECURITY-CRITICAL in `locales/en/vault.json` so that a translator
 *    cannot make it more helpful.
 *  - The exception is a body that will not decrypt after a slot has unwrapped.
 *    At that point the file is damaged rather than the credentials wrong, and
 *    being specific leaks nothing to anyone who could not already open it.
 *
 * Every other failure — an unreadable key file, an unavailable keychain, a
 * mistyped recovery key, a tampered header — carries a message the core wrote
 * to be shown, and this screen shows it. Flattening those into "That did not
 * unlock the vault." sends someone hunting for a typo they never made.
 *
 * The typed password lives in component state only long enough to reach
 * `vault_unlock`. It is never a query key, a mutation variable or part of any
 * message — mutation variables are retained in the query cache, which is a
 * copy of the secret nobody asked for, and a translated message holds whatever
 * is interpolated into it for as long as the render lasts.
 */

import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";

import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import { TextInput } from "@/components/TextInput";
import { formatBytes, i18n, isolate, isolateLtr, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { Backup, IpcFailure, KdfParams, Slot, SlotKind, UnlockRequest } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";
import { useSessions } from "@/features/sessions";

import type { RelockNotice } from "./lock";
import { kdfSummary } from "./kdf";
import { folderOf, keyfileFilters, keyfileRefusal } from "./keyfile";
import { formatStamp, splitPath } from "./VaultPicker";
import s from "./UnlockScreen.module.css";

/**
 * Why this particular wait is a second rather than instant. The cost is the
 * security property — it is what makes a stolen vault file expensive to attack
 * — so it is explained rather than hidden behind a faster-looking spinner.
 *
 * Exported because the main window's KDF upgrade bar and the vault-settings
 * dialogs run Argon2id again and have to say the same thing. Two copies of
 * this sentence would drift, and the one that drifted would be the one
 * explaining a security property.
 *
 * Those callers ask for their own namespace, so this reads the vault catalogue
 * from the shared instance rather than through `useT()`; see the header of
 * `keyfile.ts`, which requests the namespace for exactly this reason.
 */
export function kdfNote(locale: string, kdf: KdfParams | null): string {
  const t = i18n().getFixedT(null, "vault");
  const summary = kdfSummary(locale, kdf);
  // `kdfSummary` composes notation — a name, a byte figure, `t=` and `p=` —
  // which reads left to right whatever the interface language is, so it is
  // isolated before it goes into a sentence that may not.
  return summary === null
    ? t("kdf.slow")
    : t("kdf.slowWithSummary", { summary: isolateLtr(summary) });
}

const SLOT_ICONS = {
  password: "lock",
  recovery: "key",
  fido2: "usb",
  keychain: "shield",
} as const satisfies Record<SlotKind, "lock" | "key" | "usb" | "shield">;

/**
 * The countdown the interface enforces between attempts. The core rate-limits
 * independently; this exists so the delay is visible rather than felt as a
 * frozen button.
 */
const BACKOFF_SECONDS = [0, 3, 5, 10, 20, 30] as const;

function backoffFor(attempt: number): number {
  const index = Math.min(attempt, BACKOFF_SECONDS.length - 1);
  return BACKOFF_SECONDS[index] ?? 0;
}

/**
 * Does this failure mean "the file itself is damaged" rather than "those were
 * the wrong credentials"?
 *
 * The code strings are produced by `crates/remoter-ipc/src/error.rs`. These
 * are the ones that offer the rolling backups as the way out.
 */
function isBodyDamaged(failure: IpcFailure): boolean {
  return /corrupt|damaged/i.test(failure.code);
}

/**
 * The one code that must stay uninformative, because it is the one raised when
 * a credential did not unwrap a slot. Every other code names something the
 * user can act on, and is shown as the core wrote it.
 */
const CREDENTIAL_FAILURE_CODE = "vault.unlock-failed";

function isCredentialFailure(failure: IpcFailure): boolean {
  return failure.code === CREDENTIAL_FAILURE_CODE;
}

/** A hardware slot beats typing a passphrase, so it leads. */
const SLOT_ORDER: Record<SlotKind, number> = {
  fido2: 0,
  keychain: 1,
  password: 2,
  recovery: 3,
};

function canUse(slot: Slot): boolean {
  // fido2 has no unlock path in this version; the row is rendered so the vault
  // does not appear to have lost a slot, but it cannot be selected.
  return slot.kind !== "fido2";
}

/**
 * What the screen says when the vault locked under the user rather than being
 * opened by them. Null on a cold open, and then nothing extra is drawn.
 */
interface UnlockScreenProps {
  path: string;
  relock: RelockNotice | null;
}

export function UnlockScreen({ path, relock }: UnlockScreenProps) {
  const t = useT("vault");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const go = useApp((state) => state.go);

  const probe = useQuery({
    // Built, not spelled out: the picker probes the same file for its detail
    // panel, and two spellings of one key are two caches that drift apart.
    queryKey: qk.vaultProbe(path),
    queryFn: () => ipc.probeVault(path),
  });

  const [selectedIndex, setSelectedIndex] = useState<number | null>(null);
  const [password, setPassword] = useState("");
  const [keyfileChoice, setKeyfileChoice] = useState<string | null>(null);
  const [recovery, setRecovery] = useState("");
  const [keyfileDialogError, setKeyfileDialogError] = useState<string | null>(null);
  const [keyfileBrowsing, setKeyfileBrowsing] = useState(false);
  const [attempts, setAttempts] = useState(0);
  const [waitUntil, setWaitUntil] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const attemptsRef = useRef(0);

  const slots = useMemo(() => {
    const list = [...(probe.data?.slots ?? [])];
    list.sort((a, b) => SLOT_ORDER[a.kind] - SLOT_ORDER[b.kind] || a.index - b.index);
    return list;
  }, [probe.data]);

  const active =
    slots.find((slot) => slot.index === selectedIndex) ?? slots.find(canUse) ?? null;

  /**
   * The key file this machine last opened the vault with, offered back so the
   * slot is not blocked on a browse the user has no way to get right: the
   * dialog opens on the vault's own folder, the `.rvault` is the obvious file
   * in it, and choosing it fails with the one message that is not allowed to
   * explain itself. The path is not a secret — the file's contents are, and
   * they stay in the core.
   */
  const rememberedKeyfile = probe.data?.rememberedKeyfile ?? null;
  const keyfilePath = keyfileChoice ?? rememberedKeyfile;
  const keyfileIsRemembered = keyfileChoice === null && rememberedKeyfile !== null;

  /**
   * Set when the chosen path cannot be this vault's key file — the vault
   * itself, or one of its rolling backups. Stated rather than warned about:
   * it is a certainty, and letting it through produces the one failure
   * message that cannot explain itself.
   */
  const keyfileRefused = keyfileRefusal(keyfilePath ?? "", path);

  const unlock = useMutation({
    // No mutation variables: the request carries the password, and mutation
    // variables outlive the call inside the query cache.
    mutationFn: async () => {
      const method = buildRequest();
      // Unreachable while the submit button is guarded; typed rather than
      // asserted so a future caller cannot slip past the guard silently. It is
      // still translated, because "should be unreachable" is not "is".
      if (method === null) throw new Error(t("unlock.noMethodSelected"));
      return ipc.unlockVault(path, method);
    },
    onSuccess: () => go({ name: "main" }),
    onError: (error: unknown) => {
      // The backoff exists to slow guessing. A key file that could not be read
      // or an unavailable keychain is not a guess, so it does not count as an
      // attempt and does not make the user wait.
      if (!isCredentialFailure(asFailure(error))) return;
      const next = attemptsRef.current + 1;
      attemptsRef.current = next;
      setAttempts(next);
      setWaitUntil(Date.now() + backoffFor(next) * 1000);
    },
  });

  function buildRequest(): UnlockRequest | null {
    if (active === null) return null;
    switch (active.kind) {
      case "password":
        return { kind: "password", password, keyfilePath };
      case "recovery":
        // The core compares the normalised form; grouping is a reading aid.
        return { kind: "recovery", key: recovery.replace(/[^0-9a-z]/gi, "").toUpperCase() };
      case "keychain":
        return { kind: "keychain" };
      case "fido2":
        return null;
    }
  }

  // Opening a backup keeps this screen mounted with a different path. The
  // attempt count and any typed credential belong to the old file.
  useEffect(() => {
    setSelectedIndex(null);
    setPassword("");
    setKeyfileChoice(null);
    setRecovery("");
    setKeyfileDialogError(null);
    setAttempts(0);
    setWaitUntil(null);
    attemptsRef.current = 0;
    unlock.reset();
    // `unlock` is stable for the life of the component; the path is what matters.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path]);

  useEffect(() => {
    if (waitUntil === null) return;
    const id = window.setInterval(() => setNow(Date.now()), 250);
    return () => window.clearInterval(id);
  }, [waitUntil]);

  const secondsLeft =
    waitUntil === null ? 0 : Math.max(0, Math.ceil((waitUntil - now) / 1000));

  const failure = unlock.error === null ? null : asFailure(unlock.error);
  const damaged = failure !== null && isBodyDamaged(failure);
  const wrongCredential = failure !== null && isCredentialFailure(failure);
  // Everything else the core can raise here: it wrote a message for it, and
  // this is the only place the user will see it.
  const refusal = failure !== null && !damaged && !wrongCredential ? failure : null;

  /**
   * The dialog plugin rejects when the platform's file browser cannot start.
   * Left unhandled, Browse becomes a button that does nothing — and the slot
   * then refuses to unlock for a reason the user never saw.
   */
  async function chooseKeyfile() {
    let picked: string | string[] | null;
    setKeyfileBrowsing(true);
    try {
      picked = await open({
        title: t("unlock.keyfileDialogTitle"),
        multiple: false,
        directory: false,
        // Named first so the right file is obvious; "All files" second because
        // any file can be a key file and a hard filter would lock out anyone
        // whose key file is a .pem or a photograph.
        filters: keyfileFilters(),
        // Land on the file that worked last time, or at least in the vault's
        // own folder rather than wherever the process happens to start.
        defaultPath: rememberedKeyfile ?? folderOf(path),
      });
    } catch {
      setKeyfileDialogError(t("unlock.keyfileDialogFailed"));
      return;
    } finally {
      setKeyfileBrowsing(false);
    }
    setKeyfileDialogError(null);
    const chosen = Array.isArray(picked) ? picked[0] : picked;
    if (typeof chosen === "string") setKeyfileChoice(chosen);
  }

  const keyfileMissing =
    active?.kind === "password" && active.requiresKeyfile && keyfilePath === null;
  const keyfileUnusable =
    active?.kind === "password" && active.requiresKeyfile && keyfileRefused !== null;

  const canSubmit =
    active !== null &&
    canUse(active) &&
    !unlock.isPending &&
    secondsLeft === 0 &&
    !keyfileMissing &&
    !keyfileUnusable &&
    (active.kind !== "password" || password.length > 0) &&
    (active.kind !== "recovery" || recovery.trim().length > 0);

  /**
   * What the disabled Unlock button is waiting for. Ordered the way the user
   * would fix them: the thing to choose, then the thing to type, then the
   * wait.
   */
  const blockedBecause: string | null = canSubmit
    ? null
    : unlock.isPending
      ? // The button says what it is doing; repeating it beside itself would
        // crowd the row and say nothing new.
        null
      : active === null
        ? t("unlock.blocked.noSlot")
        : !canUse(active)
          ? t("unlock.blocked.fido2")
          : keyfileMissing
            ? t("unlock.blocked.keyfile")
            : keyfileUnusable
              ? t("keyfile.blockedIsVault")
              : active.kind === "password" && password.length === 0
                ? t("unlock.blocked.password")
                : active.kind === "recovery" && recovery.trim().length === 0
                  ? t("unlock.blocked.recovery")
                  : secondsLeft > 0
                    ? t("unlock.blocked.backoff", { seconds: secondsLeft })
                    : null;

  return (
    <div className={s.screen}>
      <header className={s.titlebar} data-tauri-drag-region>
        <Mark size={18} />
        <span className={s.titleText}>
          {relock === null ? t("unlock.windowTitle") : t("relock.windowTitle")}
        </span>
      </header>

      <div className={s.centre}>
        <div className={s.panel}>
          {/* The label is the user's own text and the path is a file path.
              Both are isolated so neither can reorder the panel around it. */}
          <div className={s.vault}>
            <Icon name="file" size={22} />
            <div className={s.vaultText}>
              <span className={s.vaultName}>
                {isolate(probe.data?.label ?? splitPath(path).name)}
              </span>
              <span className={s.vaultPath}>{isolateLtr(path)}</span>
            </div>
          </div>

          {/* Above everything the screen asks for, because it explains why the
              screen is here at all. A user who walked back to a window that
              had emptied itself needs that before they need a password box. */}
          {relock !== null && <RelockCard notice={relock} />}

          {probe.isPending ? (
            // The slot cards in outline. Which methods this vault has is the
            // whole content of the screen, so its absence must not read as
            // "this vault has none".
            <div className={s.loading}>
              <BusyStatus label={t("probe.reading")} size={16} />
              <div className={s.loadingSlots}>
                <SkeletonRows count={2} height="var(--space-10)" widths={["100%"]} />
              </div>
            </div>
          ) : probe.isError ? (
            <>
              <FailureNotice
                failure={asFailure(probe.error)}
                title={t("unlock.probeFailed")}
                onRetry={() => void probe.refetch()}
                retryLabel={tCommon("action.retry")}
              />
              <ExitActions onLeave={() => go({ name: "picker" })} />
            </>
          ) : damaged ? (
            <DamagedFile
              backups={probe.data.backups}
              onOpenBackup={(backupPath) =>
                // A different file, chosen from a list: a cold open like any
                // other, whatever brought the user to this screen.
                go({ name: "unlock", path: backupPath, relock: null })
              }
            />
          ) : slots.length === 0 ? (
            <>
              <Callout tone="danger" title={t("unlock.probeFailed")}>
                <p className={s.body}>{t("unlock.noSlots")}</p>
              </Callout>
              <ExitActions onLeave={() => go({ name: "picker" })} />
            </>
          ) : (
            <form
              className={s.slots}
              onSubmit={(event) => {
                event.preventDefault();
                if (canSubmit) unlock.mutate();
              }}
            >
              {slots.map((slot) => (
                <SlotCard
                  key={slot.index}
                  slot={slot}
                  active={active?.index === slot.index}
                  onSelect={() => setSelectedIndex(slot.index)}
                >
                  {slot.kind === "password" && active?.index === slot.index ? (
                    <div className={s.cardBody}>
                      <Field label={t("slot.password")} help="" error="" htmlFor="unlock-password">
                        <TextInput
                          id="unlock-password"
                          value={password}
                          onChange={setPassword}
                          type="password"
                          placeholder=""
                          mono={false}
                          autoFocus
                          disabled={unlock.isPending}
                          invalid={failure !== null}
                          ariaLabel={t("slot.password")}
                        />
                      </Field>

                      {slot.requiresKeyfile ? (
                        <div className={s.keyfile}>
                          <span className={s.keyfileLabel}>{t("keyfile.label")}</span>
                          <span className={s.keyfileValue}>
                            {keyfilePath === null ? (
                              <span className={s.keyfileEmpty}>{t("unlock.keyfileMissing")}</span>
                            ) : (
                              <>
                                <Icon name="file" size={13} />
                                <span className={s.keyfileName}>
                                  {isolate(splitPath(keyfilePath).name)}
                                </span>
                                <span className={s.keyfileDir}>
                                  {isolateLtr(splitPath(keyfilePath).dir)}
                                </span>
                              </>
                            )}
                          </span>
                          <BusyButton
                            variant="secondary"
                            size="sm"
                            type="button"
                            busy={keyfileBrowsing}
                            busyLabel={tCommon("action.opening")}
                            disabled={unlock.isPending}
                            onClick={() => void chooseKeyfile()}
                          >
                            {tCommon("action.browse")}
                          </BusyButton>
                        </div>
                      ) : null}

                      {/* A certainty, not a warning: this file cannot be this
                          vault's key file, whatever the dialog allowed. */}
                      {slot.requiresKeyfile && keyfileRefused !== null ? (
                        <p className={s.inlineError} role="alert">
                          {keyfileRefused}
                        </p>
                      ) : null}

                      {slot.requiresKeyfile && keyfileIsRemembered && keyfileRefused === null ? (
                        <p className={s.bodyNote}>{t("unlock.keyfileRemembered")}</p>
                      ) : null}

                      {slot.requiresKeyfile && keyfileDialogError !== null ? (
                        <p className={s.inlineError} role="alert">
                          {keyfileDialogError}
                        </p>
                      ) : null}
                    </div>
                  ) : null}

                  {slot.kind === "recovery" && active?.index === slot.index ? (
                    <div className={s.cardBody}>
                      <Field
                        label={t("slot.recovery")}
                        help={t("unlock.recoveryHelp")}
                        error=""
                        htmlFor="unlock-recovery"
                      >
                        <TextInput
                          id="unlock-recovery"
                          value={recovery}
                          onChange={setRecovery}
                          type="text"
                          placeholder={t("unlock.recoveryPlaceholder")}
                          mono
                          autoFocus
                          disabled={unlock.isPending}
                          invalid={failure !== null}
                          ariaLabel={t("slot.recovery")}
                        />
                      </Field>
                    </div>
                  ) : null}

                  {slot.kind === "fido2" ? (
                    <p className={s.cardNote}>{t("unlock.fido2Unavailable")}</p>
                  ) : null}

                  {slot.kind === "keychain" && active?.index === slot.index ? (
                    <p className={s.cardNote}>{t("unlock.keychainHelp")}</p>
                  ) : null}
                </SlotCard>
              ))}

              {/* A wrong credential says only this, whatever the factor was.
                  See the module comment; the rule is a security one. */}
              {wrongCredential ? (
                <div className={s.failure} role="alert">
                  <Icon name="alert" size={15} />
                  <span className={s.failureText}>{t("unlock.failed")}</span>
                  {/* The count and the countdown are one message: a separator
                      spliced between two of them is layout the translator
                      cannot move. */}
                  <span className={s.failureMeta}>
                    {secondsLeft > 0
                      ? t("unlock.attemptWaiting", { attempt: attempts, seconds: secondsLeft })
                      : t("unlock.attempt", { count: attempts })}
                  </span>
                </div>
              ) : null}

              {/* Anything else the core refused: shown as the core wrote it,
                  because it names something the user can actually fix. */}
              {refusal !== null ? (
                <FailureNotice failure={refusal} title={t("unlock.refused")} />
              ) : null}

              {/* Argon2id is about a second here by design. Left unexplained
                  the delay reads as a hang; said out loud it reads as the
                  security property it is. */}
              {unlock.isPending && (
                <div className={s.busyStrip}>
                  <BusyStatus
                    label={t("unlock.derivingStage")}
                    note={kdfNote(locale, active?.kdf ?? null)}
                    size={16}
                  />
                </div>
              )}

              <div className={s.actions}>
                <button
                  type="button"
                  className={s.link}
                  disabled={unlock.isPending}
                  onClick={() => go({ name: "picker" })}
                >
                  {t("unlock.differentVault")}
                </button>
                <span className={s.spacer} />
                {/* Why Unlock cannot be pressed, beside Unlock. */}
                {blockedBecause !== null && (
                  <span className={s.blocked}>{blockedBecause}</span>
                )}
                <Button
                  variant="secondary"
                  size="md"
                  type="button"
                  disabled={unlock.isPending}
                  onClick={() => go({ name: "picker" })}
                >
                  {tCommon("action.cancel")}
                </Button>
                <BusyButton
                  variant="primary"
                  size="md"
                  type="submit"
                  busy={unlock.isPending}
                  busyLabel={t("unlock.deriving")}
                  disabled={!canSubmit}
                  {...(blockedBecause === null ? {} : { title: blockedBecause })}
                >
                  {t("unlock.action")}
                </BusyButton>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Why this window emptied, and what became of what was running in it.
 *
 * Three things, in the order a returning user asks them. What happened. Where
 * the connections went — they are in the file, not lost, which is the sentence
 * that stops someone going to look for a backup they do not need. And what
 * happened to the sessions, which is the only one of the three the application
 * cannot answer from a constant.
 *
 * The session count is read live rather than from the snapshot taken when the
 * lock was noticed. Under a `disconnect_all` policy the core's close events
 * land a moment after the lock does, so a snapshot would have said "four
 * sessions are still connected" about four sessions that were already gone.
 * The total is the snapshot — the store no longer knows how many there were —
 * and the difference between the two is how many went.
 */
function RelockCard({ notice }: { notice: RelockNotice }) {
  const t = useT("vault");
  const total = notice.sessions.total;
  const running = useSessions(
    (st) => st.order.filter((tabId) => st.byId[tabId]?.phase === "running").length,
  );

  // Two counts rather than three phrasings of one. A vault whose policy
  // disconnected everything shows the first sentence, one that kept them
  // shows the second, and a mixture — some ended on their own before the lock
  // — shows both, which is the case a single sentence could only lie about.
  const closed = Math.max(0, total - running);

  return (
    <Callout tone="warning" title={t("relock.title")}>
      <p className={s.body}>{t(`relock.reason.${notice.reason}`)}</p>
      <p className={s.body}>{t("relock.cleared")}</p>
      {closed > 0 && (
        <p className={s.bodyNote}>{t("relock.sessions.closed", { count: closed })}</p>
      )}
      {running > 0 && (
        <p className={s.bodyNote}>{t("relock.sessions.running", { count: running })}</p>
      )}
    </Callout>
  );
}

/** The way back when there is nothing on this screen left to try. */
function ExitActions({ onLeave }: { onLeave: () => void }) {
  const t = useT("vault");
  return (
    <div className={s.actions}>
      <span className={s.spacer} />
      <Button variant="secondary" size="md" onClick={onLeave}>
        {t("unlock.differentVault")}
      </Button>
    </div>
  );
}

// ------------------------------------------------------------------ slots ---

function SlotCard({
  slot,
  active,
  onSelect,
  children,
}: {
  slot: Slot;
  active: boolean;
  onSelect: () => void;
  children: ReactNode;
}) {
  const t = useT("vault");
  const { code: locale } = useLocale();
  // Notation, composed here rather than shipped from the core; see `kdf.ts`.
  const summary = kdfSummary(locale, slot.kdf);
  const usable = canUse(slot);
  const classes = [s.card, active ? s.cardActive : "", usable ? "" : s.cardDisabled]
    .filter(Boolean)
    .join(" ");

  const name =
    slot.kind === "password"
      ? t("slot.password")
      : slot.kind === "recovery"
        ? t("slot.recovery")
        : slot.kind === "fido2"
          ? t("slot.fido2")
          : t("slot.keychain");

  const right =
    slot.kind === "fido2" ? (
      <span className={s.fastest}>{t("unlock.fido2Fastest")}</span>
    ) : slot.kind === "recovery" ? (
      <span className={s.rightMeta}>{t("unlock.recoveryLastResort")}</span>
    ) : slot.kind === "password" && summary !== null ? (
      <span className={s.chip}>{isolateLtr(summary)}</span>
    ) : null;

  return (
    <div className={classes}>
      <label className={s.cardHead}>
        <input
          type="radio"
          name="unlock-slot"
          className={s.radio}
          checked={active}
          disabled={!usable}
          onChange={onSelect}
        />
        <Icon name={SLOT_ICONS[slot.kind]} size={15} />
        <span className={s.slotName}>{name}</span>
        {/* The slot's own label is whatever the user called it. */}
        {slot.label.length > 0 && slot.label !== name ? (
          <span className={s.chip}>{isolate(slot.label)}</span>
        ) : null}
        <span className={s.spacer} />
        {right}
      </label>
      {children}
    </div>
  );
}

// -------------------------------------------------------- damaged vault ----

function DamagedFile({
  backups,
  onOpenBackup,
}: {
  backups: Backup[];
  onOpenBackup: (path: string) => void;
}) {
  const t = useT("vault");
  const { code: locale } = useLocale();
  const go = useApp((state) => state.go);

  return (
    <div className={s.damaged}>
      <Callout tone="warning" title={t("unlock.damaged.title")}>
        <p className={s.body}>{t("unlock.damaged.body")}</p>
      </Callout>

      <div className={s.damagedHead}>{t("unlock.damaged.backups")}</div>

      {backups.length === 0 ? (
        <p className={s.cardNote}>{t("unlock.damaged.noBackups")}</p>
      ) : (
        <ul className={s.backups}>
          {backups.map((backup, index) => (
            <li key={backup.path}>
              <button
                type="button"
                className={index === 0 ? `${s.backup} ${s.backupCurrent}` : s.backup}
                onClick={() => onOpenBackup(backup.path)}
              >
                <span className={index === 0 ? s.dotCurrent : s.dot} />
                <span className={s.backupStamp}>{formatStamp(locale, backup.modifiedAt)}</span>
                <span className={s.backupSize}>{formatBytes(locale, backup.sizeBytes)}</span>
                <span className={s.spacer} />
                <span className={index === 0 ? s.backupActionStrong : s.backupAction}>
                  {index === 0 ? t("unlock.damaged.openNewest") : t("unlock.damaged.openOther")}
                </span>
              </button>
            </li>
          ))}
        </ul>
      )}

      <ExitActions onLeave={() => go({ name: "picker" })} />
    </div>
  );
}
