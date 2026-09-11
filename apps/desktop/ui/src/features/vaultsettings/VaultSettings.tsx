/**
 * Vault settings: the keys that open this file, and the rules that travel
 * inside it.
 *
 * Four panels behind a vertical tab list, as in
 * ui_parts/project_ui_design/08 Vault Settings. Everything here belongs to the
 * vault rather than to the machine — a vault carried to another computer
 * carries its auto-lock, its recording policy and its backup count with it,
 * which is why these are not in application settings.
 *
 * The screen owns the reads and the settings write. Slot administration owns
 * itself, in `KeySlotsSection`, because a slot change invalidates three caches
 * and every one of its commands can fail in a way the user has to see.
 *
 * Both halves of every round trip are visible. Until a read lands the panel
 * says what it is waiting for; when one fails it shows the core's own message
 * with a way to try again. A settings screen that silently shows defaults is a
 * settings screen that quietly loses your settings — and on this screen the
 * defaults would be a claim about who can open your vault.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { KeyboardEvent } from "react";

import { BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { useAnyModalOpen } from "@/hooks/useModalRegistration";
import { formatNumber, isolate, useLocale, useT } from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { VaultSettings as VaultSettingsDto, VaultSettingsPatch } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { AutoLockSection } from "./AutoLockSection";
import { BackupsSection } from "./BackupsSection";
import { KeySlotsSection } from "./KeySlotsSection";
import { RecordingSection } from "./RecordingSection";
import { vaultAdminKeys } from "./keys";
import type { VaultSaveFailure, VaultSettingsField } from "./types";
import s from "./VaultSettings.module.css";

/**
 * The four panels, as ids paired with the catalogue key that names them.
 *
 * Keys, not labels: this array is module-level, so a label resolved here would
 * be frozen in whatever language the application started in and would not
 * follow a language change.
 */
const TABS = [
  { id: "slots", labelKey: "screen.navSlots" },
  { id: "lock", labelKey: "screen.navLock" },
  { id: "recording", labelKey: "screen.navRecording" },
  { id: "backups", labelKey: "screen.navBackups" },
] as const;

type TabId = (typeof TABS)[number]["id"];

interface SaveVariables {
  field: VaultSettingsField;
  patch: VaultSettingsPatch;
}

export function VaultSettings() {
  const t = useT("vaultsettings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const goBack = useApp((state) => state.goBack);
  const modalOpen = useAnyModalOpen();
  const queryClient = useQueryClient();

  const [tab, setTab] = useState<TabId>("slots");
  const [failure, setFailure] = useState<VaultSaveFailure | null>(null);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  const vaultState = useQuery({ queryKey: qk.vaultState(), queryFn: ipc.vaultState });
  const slots = useQuery({ queryKey: vaultAdminKeys.slots(), queryFn: ipc.vaultSlots });
  const settings = useQuery({
    queryKey: vaultAdminKeys.settings(),
    queryFn: ipc.getVaultSettings,
  });

  const save = useMutation<VaultSettingsDto, unknown, SaveVariables>({
    mutationFn: (variables) => ipc.setVaultSettings(variables.patch),
    onSuccess: (next) => {
      setFailure(null);
      queryClient.setQueryData(vaultAdminKeys.settings(), next);
      // The idle timeout is what the footer's countdown reads from.
      void queryClient.invalidateQueries({ queryKey: qk.vaultState() });
    },
    onError: (error, variables) => {
      setFailure({ field: variables.field, failure: asFailure(error) });
    },
  });

  /*
   * Escape leaves, as it does from every other panel — but not while a dialog
   * is open over this one. The dialogs swallow the press themselves; this is
   * the second half of that agreement, so that a dialog whose own handler has
   * not yet mounted cannot leak one Escape into the screen behind it.
   */
  useEffect(() => {
    function onKey(event: globalThis.KeyboardEvent) {
      if (event.key !== "Escape" || modalOpen) return;
      goBack();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goBack, modalOpen]);

  function onTabKeyDown(event: KeyboardEvent<HTMLDivElement>) {
    const current = TABS.findIndex((entry) => entry.id === tab);
    let target: number;

    if (event.key === "ArrowDown" || event.key === "ArrowRight") target = current + 1;
    else if (event.key === "ArrowUp" || event.key === "ArrowLeft") target = current - 1;
    else if (event.key === "Home") target = 0;
    else if (event.key === "End") target = TABS.length - 1;
    else return;

    event.preventDefault();
    const wrapped = (target + TABS.length) % TABS.length;
    const next = TABS[wrapped];
    if (next === undefined) return;

    setTab(next.id);
    tabRefs.current[wrapped]?.focus();
  }

  const loadedSettings = settings.data;
  const loadedSlots = slots.data;
  const vaultLabel = vaultState.data?.label ?? null;
  const vaultPath = vaultState.data?.path ?? "";

  /**
   * The Argon2id summary a recovery key sheet is printed with. Taken from a
   * password slot because that is the only slot kind that has one.
   */
  const kdfSummary =
    loadedSlots?.slots.find((slot) => slot.kdfSummary !== null && slot.kdfSummary !== "")
      ?.kdfSummary ?? null;

  const sectionProps = {
    onSave: (field: VaultSettingsField, patch: VaultSettingsPatch) => save.mutate({ field, patch }),
    savingField:
      save.isPending && save.variables !== undefined ? save.variables.field : null,
    failure,
    onRetrySave: () => {
      const last = save.variables;
      if (last !== undefined) save.mutate(last);
    },
  };

  const needsSettings = tab !== "slots";

  return (
    <div className={s.screen}>
      <header className={s.header}>
        <span className={s.headerIcon} aria-hidden="true">
          <Icon name="shield" size={15} />
        </span>
        <h1 className={s.headerTitle}>{t("screen.title")}</h1>
        {vaultLabel !== null && (
          // The vault's own name, isolated: a label written in a right-to-left
          // script must not reorder the title beside it, or an ASCII one the
          // Arabic interface around it.
          <span className={s.headerVault}>
            {t("screen.vaultLabel", { label: isolate(vaultLabel) })}
          </span>
        )}
        <span className={s.headerSpacer} />
        <button
          type="button"
          className={s.closeButton}
          onClick={goBack}
          title={t("screen.closeHint")}
          aria-label={t("screen.close")}
        >
          <Icon name="x" size={15} />
        </button>
      </header>

      <div className={s.body}>
        <div
          className={s.nav}
          role="tablist"
          aria-orientation="vertical"
          aria-label={t("screen.sections")}
          onKeyDown={onTabKeyDown}
        >
          {TABS.map((entry, index) => (
            <button
              key={entry.id}
              type="button"
              ref={(element) => {
                tabRefs.current[index] = element;
              }}
              className={entry.id === tab ? [s.navItem, s.navItemActive].join(" ") : s.navItem}
              role="tab"
              id={`vault-settings-tab-${entry.id}`}
              aria-controls={`vault-settings-panel-${entry.id}`}
              aria-selected={entry.id === tab}
              tabIndex={entry.id === tab ? 0 : -1}
              onClick={() => setTab(entry.id)}
            >
              {t(entry.labelKey)}
              {entry.id === "slots" && loadedSlots !== undefined && (
                // Through Intl: a locale with its own numbering system draws
                // its own digits, and a slot count is still a number.
                <span className={s.navCount}>{formatNumber(locale, loadedSlots.slots.length)}</span>
              )}
            </button>
          ))}
        </div>

        <div
          className={s.panel}
          role="tabpanel"
          id={`vault-settings-panel-${tab}`}
          aria-labelledby={`vault-settings-tab-${tab}`}
          tabIndex={0}
        >
          {vaultState.data?.unlocked === false && (
            <FailureNotice
              failure={{
                code: "vault.locked",
                message: t("screen.locked"),
                detail: t("screen.lockedBody"),
                actions: [],
              }}
              tone="warning"
            >
              <Button size="sm" variant="ghost" onClick={goBack}>
                {t("screen.close")}
              </Button>
            </FailureNotice>
          )}

          {tab === "slots" && slots.isPending && (
            <div className={s.loading}>
              <BusyStatus label={t("screen.loadingSlots")} size={16} />
              <SkeletonRows count={4} height="var(--space-10)" />
            </div>
          )}

          {tab === "slots" && slots.isError && (
            <FailureNotice
              failure={asFailure(slots.error)}
              title={t("screen.slotsFailed")}
              onRetry={() => void slots.refetch()}
              retryLabel={tCommon("action.retry")}
            >
              <Button size="sm" variant="ghost" onClick={goBack}>
                {t("screen.close")}
              </Button>
            </FailureNotice>
          )}

          {tab === "slots" && loadedSlots !== undefined && (
            <KeySlotsSection
              vaultSlots={loadedSlots}
              vaultPath={vaultPath}
              kdfSummary={kdfSummary}
            />
          )}

          {needsSettings && settings.isPending && (
            <div className={s.loading}>
              <BusyStatus label={t("screen.loadingSettings")} size={16} />
              <SkeletonRows count={3} height="var(--space-8)" />
            </div>
          )}

          {needsSettings && settings.isError && (
            <FailureNotice
              failure={asFailure(settings.error)}
              title={t("screen.settingsFailed")}
              onRetry={() => void settings.refetch()}
              retryLabel={tCommon("action.retry")}
            >
              <Button size="sm" variant="ghost" onClick={goBack}>
                {t("screen.close")}
              </Button>
            </FailureNotice>
          )}

          {loadedSettings !== undefined && tab === "lock" && (
            <AutoLockSection settings={loadedSettings} {...sectionProps} />
          )}
          {loadedSettings !== undefined && tab === "recording" && (
            <RecordingSection settings={loadedSettings} {...sectionProps} />
          )}
          {loadedSettings !== undefined && tab === "backups" && (
            <BackupsSection
              settings={loadedSettings}
              backupsPresent={loadedSlots?.backupCount ?? 0}
              {...sectionProps}
            />
          )}
        </div>
      </div>
    </div>
  );
}
