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
 *    only one this screen replaces with the fixed sentence.
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
 * copy of the secret nobody asked for.
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
import { asFailure, ipc } from "@/lib/ipc";
import type { Backup, IpcFailure, Slot, SlotKind, UnlockRequest } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { folderOf, keyfileFilters, keyfileRefusal } from "./keyfile";
import { formatBytes, formatStamp, splitPath } from "./VaultPicker";
import s from "./UnlockScreen.module.css";

/**
 * Why this particular wait is a second rather than instant. The cost is the
 * security property — it is what makes a stolen vault file expensive to attack
 * — so it is explained rather than hidden behind a faster-looking spinner.
 *
 * Exported because the main window's KDF upgrade bar runs Argon2id again and
 * has to say the same thing. Two copies of this sentence would drift, and the
 * one that drifted would be the one explaining a security property.
 */
export function kdfNote(summary: string | null): string {
  return summary === null
    ? "Key derivation is deliberately slow. That cost is what makes a stolen vault file expensive to attack."
    : `Key derivation is deliberately slow — ${summary}. That cost is what makes a stolen vault file expensive to attack.`;
}

const TEXT = {
  windowTitle: "Unlock vault",

  probing: "Reading the vault header…",
  probeFailed: "This vault could not be opened.",
  differentVault: "Open a different vault",
  cancel: "Cancel",
  unlock: "Unlock",
  /**
   * Short enough that reserving room for it does not widen the idle Unlock
   * button; the full stage is said in the status line above the row.
   */
  unlocking: "Deriving…",
  /** Not "Unlocking…": naming the stage says the wait is expected. */
  unlockingStage: "Deriving the key from what you typed…",
  /** Defined above, and shared with the main window's KDF upgrade bar. */
  kdfNote,

  noSlots:
    "This vault's header lists no usable unlock methods. That should not happen; the file is likely damaged.",

  password: "Master password",
  passwordHelp: "",
  keyfile: "Key file",
  keyfileBrowse: "Browse",
  keyfileBrowsing: "Opening…",
  keyfileMissing: "This slot also needs its key file before it can unlock.",
  keyfileDialog: "Choose the key file for this vault",
  keyfileDialogFailed:
    "The system file browser did not open, so no key file could be chosen. Nothing was sent to the vault.",
  keyfileRemembered:
    "This is the key file this machine last opened the vault with. Browse to choose a different one.",
  /** The vault picked as its own key file — the mistake this screen invites. */
  blockedKeyfileRefused: "That file cannot be this vault's key file.",

  recovery: "Recovery key",
  recoveryRight: "Last resort",
  recoveryHelp: "Spaces, dashes and capitalisation are ignored.",
  recoveryPlaceholder: "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX",

  securityKey: "Security key",
  fastest: "fastest",
  fido2Unavailable:
    "This vault has a security key slot, but touch-to-unlock is not implemented in this version. Use another method for now.",

  keychain: "Remember on this device",
  keychainHelp: "Held by the system keychain. Nothing to type — press Unlock.",

  /** Exactly this string, whatever the factor was. See the module comment. */
  failed: "That did not unlock the vault.",
  attempt: (n: number) => `Attempt ${n}`,
  waiting: (seconds: number) => `next attempt in ${seconds} s`,
  refused: "The vault refused to open.",

  /** Why the Unlock button will not respond, in the order it becomes true. */
  blockedNoSlot: "Choose an unlock method above.",
  blockedFido2: "This vault's security key slot cannot be used in this version.",
  blockedKeyfile: "Choose the key file this slot needs.",
  blockedPassword: "Type the master password.",
  blockedRecovery: "Type the recovery key.",
  blockedBackoff: (seconds: number) =>
    `Waiting ${seconds} s before the next attempt after a failed one.`,

  corruptTitle: "Your credentials were right. The file is damaged.",
  corruptBody:
    "Remoter unwrapped your key slot successfully, then could not decrypt the body of the vault. That means the file changed after it was written — not that you typed anything wrong.",
  corruptBackups: "Rolling backups on this machine",
  corruptOpen: "Open this instead",
  corruptOpenOther: "Open",
  corruptNoBackups:
    "There are no rolling backups beside this file. A copy from your own backups is the way back.",
} as const;

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

export function UnlockScreen({ path }: { path: string }) {
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
      // asserted so a future caller cannot slip past the guard silently.
      if (method === null) throw new Error("No unlock method is selected.");
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
        title: TEXT.keyfileDialog,
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
      setKeyfileDialogError(TEXT.keyfileDialogFailed);
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
        ? TEXT.blockedNoSlot
        : !canUse(active)
          ? TEXT.blockedFido2
          : keyfileMissing
            ? TEXT.blockedKeyfile
            : keyfileUnusable
              ? TEXT.blockedKeyfileRefused
              : active.kind === "password" && password.length === 0
              ? TEXT.blockedPassword
              : active.kind === "recovery" && recovery.trim().length === 0
                ? TEXT.blockedRecovery
                : secondsLeft > 0
                  ? TEXT.blockedBackoff(secondsLeft)
                  : null;

  return (
    <div className={s.screen}>
      <header className={s.titlebar} data-tauri-drag-region>
        <Mark size={18} />
        <span className={s.titleText}>{TEXT.windowTitle}</span>
      </header>

      <div className={s.centre}>
        <div className={s.panel}>
          <div className={s.vault}>
            <Icon name="file" size={22} />
            <div className={s.vaultText}>
              <span className={s.vaultName}>{probe.data?.label ?? splitPath(path).name}</span>
              <span className={s.vaultPath}>{path}</span>
            </div>
          </div>

          {probe.isPending ? (
            // The slot cards in outline. Which methods this vault has is the
            // whole content of the screen, so its absence must not read as
            // "this vault has none".
            <div className={s.loading}>
              <BusyStatus label={TEXT.probing} size={16} />
              <div className={s.loadingSlots}>
                <SkeletonRows count={2} height="var(--space-10)" widths={["100%"]} />
              </div>
            </div>
          ) : probe.isError ? (
            <>
              <FailureNotice
                failure={asFailure(probe.error)}
                title={TEXT.probeFailed}
                onRetry={() => void probe.refetch()}
              />
              <ExitActions onLeave={() => go({ name: "picker" })} />
            </>
          ) : damaged ? (
            <DamagedFile
              backups={probe.data.backups}
              onOpenBackup={(backupPath) => go({ name: "unlock", path: backupPath })}
            />
          ) : slots.length === 0 ? (
            <>
              <Callout tone="danger" title={TEXT.probeFailed}>
                <p className={s.body}>{TEXT.noSlots}</p>
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
                      <Field
                        label={TEXT.password}
                        help={TEXT.passwordHelp}
                        error=""
                        htmlFor="unlock-password"
                      >
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
                          ariaLabel={TEXT.password}
                        />
                      </Field>

                      {slot.requiresKeyfile ? (
                        <div className={s.keyfile}>
                          <span className={s.keyfileLabel}>{TEXT.keyfile}</span>
                          <span className={s.keyfileValue}>
                            {keyfilePath === null ? (
                              <span className={s.keyfileEmpty}>{TEXT.keyfileMissing}</span>
                            ) : (
                              <>
                                <Icon name="file" size={13} />
                                <span className={s.keyfileName}>
                                  {splitPath(keyfilePath).name}
                                </span>
                                <span className={s.keyfileDir}>{splitPath(keyfilePath).dir}</span>
                              </>
                            )}
                          </span>
                          <BusyButton
                            variant="secondary"
                            size="sm"
                            type="button"
                            busy={keyfileBrowsing}
                            busyLabel={TEXT.keyfileBrowsing}
                            disabled={unlock.isPending}
                          onClick={() => void chooseKeyfile()}
                          >
                            {TEXT.keyfileBrowse}
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
                        <p className={s.bodyNote}>{TEXT.keyfileRemembered}</p>
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
                        label={TEXT.recovery}
                        help={TEXT.recoveryHelp}
                        error=""
                        htmlFor="unlock-recovery"
                      >
                        <TextInput
                          id="unlock-recovery"
                          value={recovery}
                          onChange={setRecovery}
                          type="text"
                          placeholder={TEXT.recoveryPlaceholder}
                          mono
                          autoFocus
                          disabled={unlock.isPending}
                          invalid={failure !== null}
                          ariaLabel={TEXT.recovery}
                        />
                      </Field>
                    </div>
                  ) : null}

                  {slot.kind === "fido2" ? (
                    <p className={s.cardNote}>{TEXT.fido2Unavailable}</p>
                  ) : null}

                  {slot.kind === "keychain" && active?.index === slot.index ? (
                    <p className={s.cardNote}>{TEXT.keychainHelp}</p>
                  ) : null}
                </SlotCard>
              ))}

              {/* A wrong credential says only this, whatever the factor was.
                  See the module comment; the rule is a security one. */}
              {wrongCredential ? (
                <div className={s.failure} role="alert">
                  <Icon name="alert" size={15} />
                  <span className={s.failureText}>{TEXT.failed}</span>
                  <span className={s.failureMeta}>
                    {TEXT.attempt(attempts)}
                    {secondsLeft > 0 ? ` · ${TEXT.waiting(secondsLeft)}` : ""}
                  </span>
                </div>
              ) : null}

              {/* Anything else the core refused: shown as the core wrote it,
                  because it names something the user can actually fix. */}
              {refusal !== null ? (
                <FailureNotice failure={refusal} title={TEXT.refused} />
              ) : null}

              {/* Argon2id is about a second here by design. Left unexplained
                  the delay reads as a hang; said out loud it reads as the
                  security property it is. */}
              {unlock.isPending && (
                <div className={s.busyStrip}>
                  <BusyStatus
                    label={TEXT.unlockingStage}
                    note={TEXT.kdfNote(active?.kdfSummary ?? null)}
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
                  {TEXT.differentVault}
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
                  {TEXT.cancel}
                </Button>
                <BusyButton
                  variant="primary"
                  size="md"
                  type="submit"
                  busy={unlock.isPending}
                  busyLabel={TEXT.unlocking}
                  disabled={!canSubmit}
                  {...(blockedBecause === null ? {} : { title: blockedBecause })}
                >
                  {TEXT.unlock}
                </BusyButton>
              </div>
            </form>
          )}
        </div>
      </div>
    </div>
  );
}

/** The way back when there is nothing on this screen left to try. */
function ExitActions({ onLeave }: { onLeave: () => void }) {
  return (
    <div className={s.actions}>
      <span className={s.spacer} />
      <Button variant="secondary" size="md" onClick={onLeave}>
        {TEXT.differentVault}
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
  const usable = canUse(slot);
  const classes = [s.card, active ? s.cardActive : "", usable ? "" : s.cardDisabled]
    .filter(Boolean)
    .join(" ");

  const name =
    slot.kind === "password"
      ? TEXT.password
      : slot.kind === "recovery"
        ? TEXT.recovery
        : slot.kind === "fido2"
          ? TEXT.securityKey
          : TEXT.keychain;

  const right =
    slot.kind === "fido2" ? (
      <span className={s.fastest}>{TEXT.fastest}</span>
    ) : slot.kind === "recovery" ? (
      <span className={s.rightMeta}>{TEXT.recoveryRight}</span>
    ) : slot.kind === "password" && slot.kdfSummary !== null ? (
      <span className={s.chip}>{slot.kdfSummary}</span>
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
        {slot.label.length > 0 && slot.label !== name ? (
          <span className={s.chip}>{slot.label}</span>
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
  const go = useApp((state) => state.go);

  return (
    <div className={s.damaged}>
      <Callout tone="warning" title={TEXT.corruptTitle}>
        <p className={s.body}>{TEXT.corruptBody}</p>
      </Callout>

      <div className={s.damagedHead}>{TEXT.corruptBackups}</div>

      {backups.length === 0 ? (
        <p className={s.cardNote}>{TEXT.corruptNoBackups}</p>
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
                <span className={s.backupStamp}>{formatStamp(backup.modifiedAt)}</span>
                <span className={s.backupSize}>{formatBytes(backup.sizeBytes)}</span>
                <span className={s.spacer} />
                <span className={index === 0 ? s.backupActionStrong : s.backupAction}>
                  {index === 0 ? TEXT.corruptOpen : TEXT.corruptOpenOther}
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
