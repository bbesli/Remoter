/**
 * The offer `docs/security/vault-format.md` promises: "If a vault's parameters
 * are below the current floor, Remoter offers to upgrade them on the next
 * successful unlock."
 *
 * `VaultState.kdfUpgradeAvailable` is the offer and `ipc.upgradeKdf` is the
 * acceptance. Both existed end to end in the core with nothing calling them, so
 * a vault created at below-floor Argon2id parameters stayed weak for the life of
 * the file while the API advertised the remedy.
 *
 * A bar, not a modal. This is a "worth doing" and not a "stop what you are
 * doing": a vault below the floor still opens, and blocking the window over it
 * teaches people to dismiss security prompts without reading them. It can be
 * put away, and it comes back on the next unlock because the state is read from
 * the vault rather than remembered here.
 *
 * The password is asked for again, and the sentence says why: the core rewraps
 * each slot around the credential, not around the master key already in memory
 * (`Vault::upgrade_kdf`). It is not a new password — the same one, re-derived at
 * stronger cost. It lives in component state only long enough to reach
 * `vault_upgrade_kdf`, and never becomes a mutation variable: TanStack keeps
 * those in the mutation cache, which would be a copy of the secret nobody asked
 * for.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";

import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { TextInput } from "@/components/TextInput";
import { useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { VaultState } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { folderOf, keyfileFilters, keyfileRefusal } from "@/features/vault/keyfile";
import { kdfNote } from "@/features/vault/UnlockScreen";
import { splitPath } from "@/features/vault/VaultPicker";

import s from "./KdfUpgradeBar.module.css";


export function KdfUpgradeBar({ vault }: { vault: VaultState | undefined }) {
  const t = useT("shell");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const queryClient = useQueryClient();

  const [expanded, setExpanded] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const [done, setDone] = useState(false);
  const [password, setPassword] = useState("");
  const [keyfileChoice, setKeyfileChoice] = useState<string | null>(null);
  const [keyfileDialogError, setKeyfileDialogError] = useState<string | null>(null);
  const [keyfileBrowsing, setKeyfileBrowsing] = useState(false);

  const path = vault?.path ?? null;
  const offered = vault?.unlocked === true && vault.kdfUpgradeAvailable && path !== null;

  /**
   * Only while the form is open: the header says whether the password slot also
   * needs a key file, and which one this machine last used. It is the same
   * cleartext read the unlock screen just did, under the same key, so this is
   * normally served from cache without touching the disk again.
   */
  const probe = useQuery({
    queryKey: qk.vaultProbe(path ?? ""),
    queryFn: () => ipc.probeVault(path ?? ""),
    enabled: expanded && path !== null,
  });

  const passwordSlots = (probe.data?.slots ?? []).filter((slot) => slot.kind === "password");
  const needsKeyfile = passwordSlots.some((slot) => slot.requiresKeyfile);
  const keyfilePath = keyfileChoice ?? probe.data?.rememberedKeyfile ?? null;
  const keyfileRefused = keyfileRefusal(keyfilePath ?? "", path ?? "");
  // The cost of the slot being replaced, so the wait is explained in the same
  // words the unlock screen used a moment ago.
  const replacedKdf = passwordSlots.find((slot) => slot.kdf !== null)?.kdf ?? null;

  const upgrade = useMutation({
    // No mutation variables: the request carries the password, and mutation
    // variables outlive the call inside the query cache.
    mutationFn: () =>
      ipc.upgradeKdf({ kind: "password", password, keyfilePath: needsKeyfile ? keyfilePath : null }),
    onSuccess: async () => {
      // Out of component state the moment the core has it. Nothing else in the
      // frontend has ever held it.
      setPassword("");
      setExpanded(false);
      setDone(true);
      // Vault state only, and not `invalidateAfterTreeChange`: rewrapping a key
      // slot does not touch the body, so no node changed and nothing needs
      // re-resolving. What did change is `kdfUpgradeAvailable`, which is what
      // takes this bar off the screen.
      await queryClient.invalidateQueries({ queryKey: qk.vaultState() });
    },
  });

  /**
   * The dialog plugin rejects when the platform's file browser cannot start —
   * no portal on a bare Wayland session, for one. Left unhandled, Browse is a
   * button that does nothing.
   */
  async function chooseKeyfile() {
    let picked: string | string[] | null;
    setKeyfileBrowsing(true);
    try {
      picked = await open({
        title: t("kdfUpgrade.keyfileDialog"),
        multiple: false,
        directory: false,
        filters: keyfileFilters(),
        defaultPath: probe.data?.rememberedKeyfile ?? folderOf(path ?? ""),
      });
    } catch {
      setKeyfileDialogError(t("kdfUpgrade.keyfileDialogFailed"));
      return;
    } finally {
      setKeyfileBrowsing(false);
    }
    setKeyfileDialogError(null);
    const chosen = Array.isArray(picked) ? picked[0] : picked;
    if (typeof chosen === "string") setKeyfileChoice(chosen);
  }

  // Kept on screen after the upgrade lands, because the offer that justified
  // this bar has just become false and the bar would otherwise vanish mid-click
  // with nothing said.
  if (done) {
    return (
      <div className={s.bar} role="status">
        <span className={s.icon} aria-hidden="true">
          <Icon name="check" size={15} />
        </span>
        <p className={s.text}>{t("kdfUpgrade.done")}</p>
        <Button variant="ghost" size="sm" onClick={() => setDone(false)}>
          {tCommon("action.dismiss")}
        </Button>
      </div>
    );
  }

  if (!offered || dismissed) return null;

  if (!expanded) {
    return (
      <div className={s.bar}>
        <span className={s.icon} aria-hidden="true">
          <Icon name="shield" size={15} />
        </span>
        <p className={s.text}>{t("kdfUpgrade.offer")}</p>
        <Button variant="secondary" size="sm" onClick={() => setExpanded(true)}>
          {t("kdfUpgrade.strengthen")}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={() => setDismissed(true)}
          ariaLabel={t("kdfUpgrade.dismissLabel")}
        >
          {t("kdfUpgrade.notNow")}
        </Button>
      </div>
    );
  }

  const keyfileBlocked = needsKeyfile && (keyfilePath === null || keyfileRefused !== null);
  const canSubmit =
    !upgrade.isPending && !probe.isPending && !probe.isError && password.length > 0 && !keyfileBlocked;
  const blockedBecause = canSubmit || upgrade.isPending
    ? null
    : keyfileBlocked
      ? t("kdfUpgrade.blockedKeyfile")
      : password.length === 0
        ? t("kdfUpgrade.blockedPassword")
        : null;

  return (
    <form
      className={s.form}
      onSubmit={(event) => {
        event.preventDefault();
        if (canSubmit) upgrade.mutate();
      }}
    >
      <p className={s.text}>{t("kdfUpgrade.offer")}</p>

      {probe.isPending ? (
        <div className={s.loading}>
          <BusyStatus label={t("kdfUpgrade.reading")} size={14} />
          <SkeletonRows count={1} height="var(--space-8)" widths={["100%"]} />
        </div>
      ) : probe.isError ? (
        // Without the header there is no way to know whether the slot needs a
        // key file, so the form cannot be filled in honestly.
        <FailureNotice
          failure={asFailure(probe.error)}
          title={t("kdfUpgrade.readFailed")}
          onRetry={() => void probe.refetch()}
          retryLabel={tCommon("action.retry")}
        />
      ) : (
        // Capped rather than window-wide: a password field the width of a
        // 2560px monitor reads as a search bar, not as a credential.
        <div className={s.fields}>
          <Field label={t("kdfUpgrade.password")} help={t("kdfUpgrade.passwordHelp")} htmlFor="kdf-upgrade-password">
            <TextInput
              id="kdf-upgrade-password"
              value={password}
              onChange={setPassword}
              type="password"
              autoFocus
              disabled={upgrade.isPending}
              invalid={upgrade.isError}
              ariaLabel={t("kdfUpgrade.password")}
            />
          </Field>

          {needsKeyfile && (
            <div className={s.keyfile}>
              <span className={s.keyfileLabel}>{t("kdfUpgrade.keyfile")}</span>
              <span className={s.keyfileValue}>
                {keyfilePath === null ? (
                  <span className={s.keyfileEmpty}>{t("kdfUpgrade.keyfileMissing")}</span>
                ) : (
                  <>
                    <Icon name="file" size={13} />
                    <span className={s.keyfileName}>{splitPath(keyfilePath).name}</span>
                  </>
                )}
              </span>
              <BusyButton
                variant="secondary"
                size="sm"
                type="button"
                busy={keyfileBrowsing}
                busyLabel={tCommon("action.opening")}
                disabled={upgrade.isPending}
                onClick={() => void chooseKeyfile()}
              >
                {tCommon("action.browse")}
              </BusyButton>
            </div>
          )}

          {/* A certainty, not a warning: a vault cannot be its own key file. */}
          {needsKeyfile && keyfileRefused !== null && (
            <p className={s.inlineError} role="alert">
              {keyfileRefused}
            </p>
          )}

          {keyfileDialogError !== null && (
            <p className={s.inlineError} role="alert">
              {keyfileDialogError}
            </p>
          )}
        </div>
      )}

      {upgrade.isError && (
        <FailureNotice failure={asFailure(upgrade.error)} title={t("kdfUpgrade.failed")} />
      )}

      {/* Argon2id runs again here, so the wait is the same wait the unlock
          screen just explained — in the same words, from the same function. */}
      {upgrade.isPending && (
        <BusyStatus label={t("kdfUpgrade.workingStage")} note={kdfNote(locale, replacedKdf)} size={16} />
      )}

      <div className={s.actions}>
        {blockedBecause !== null && <span className={s.blocked}>{blockedBecause}</span>}
        <Button
          variant="secondary"
          size="sm"
          type="button"
          disabled={upgrade.isPending}
          onClick={() => {
            setPassword("");
            setExpanded(false);
            upgrade.reset();
          }}
        >
          {tCommon("action.cancel")}
        </Button>
        <BusyButton
          variant="primary"
          size="sm"
          type="submit"
          busy={upgrade.isPending}
          busyLabel={t("kdfUpgrade.working")}
          disabled={!canSubmit}
          {...(blockedBecause === null ? {} : { title: blockedBecause })}
        >
          {t("kdfUpgrade.confirm")}
        </BusyButton>
      </div>
    </form>
  );
}
