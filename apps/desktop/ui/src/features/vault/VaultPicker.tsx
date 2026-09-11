/**
 * The launch screen: choose which vault to open.
 *
 * Two variants share this file because they answer the same question. A
 * returning user gets the list of vaults this machine remembers; someone
 * arriving with no recents gets two doors, because "pick a vault" is a
 * meaningless instruction when there are none.
 *
 * Nothing here decrypts anything. `vault_probe` reads the cleartext header
 * only, which is why the detail panel can show the format and the backups but
 * not the connection count — those live inside the encrypted body.
 */

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { open } from "@tauri-apps/plugin-dialog";
import type { TFunction } from "i18next";

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import {
  formatBytes,
  formatDateTime,
  formatRelativeTime,
  isolate,
  isolateLtr,
  useLocale,
  useT,
} from "@/i18n";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, RecentVault, SlotKind } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import s from "./VaultPicker.module.css";

/**
 * The build and its licence.
 *
 * A version string and a licence identifier: neither is translated, and
 * neither belongs in a catalogue where a translator would be asked what to do
 * with it (docs/features/i18n.md, "What is never translated").
 */
const BUILD_LINE = "v0.1.0-dev · GPL-3.0";

const SLOT_ICONS = {
  password: "lock",
  recovery: "key",
  fido2: "usb",
  keychain: "shield",
} as const satisfies Record<SlotKind, "lock" | "key" | "usb" | "shield">;

/** The tooltip on a slot badge, named rather than indexed so the keys are literals. */
function slotBadgeLabel(t: TFunction<"vault">, kind: SlotKind): string {
  switch (kind) {
    case "password":
      return t("detail.slotBadge.password");
    case "recovery":
      return t("detail.slotBadge.recovery");
    case "fido2":
      return t("detail.slotBadge.fido2");
    case "keychain":
      return t("detail.slotBadge.keychain");
  }
}

/**
 * The vault file format and its version — `rvault v3`.
 *
 * An identifier the format itself owns, like a protocol name, so it is built
 * here rather than translated. The digits are ASCII for the same reason: this
 * names a file format, it does not count anything.
 */
function formatLabel(version: number): string {
  return `rvault v${version}`;
}

// ------------------------------------------------------------ formatting ---

/**
 * The core stamps times as whole seconds in some places and milliseconds in
 * others depending on the source clock. Anything below this threshold is far
 * too small to be a millisecond timestamp in this century, so it is seconds.
 */
const SECONDS_CUTOFF = 1e12;

function toMillis(stamp: number): number {
  return stamp < SECONDS_CUTOFF ? stamp * 1000 : stamp;
}

/**
 * A backup's timestamp, in the reader's locale.
 *
 * Exported because the unlock screen lists the same backups when a vault's
 * body will not decrypt, and the seconds-or-milliseconds rule above has to be
 * applied in exactly one place.
 */
export function formatStamp(locale: string, stamp: number): string {
  return formatDateTime(locale, toMillis(stamp), "short");
}

/** Splits a path so the file name can carry the weight and the directory recedes. */
export function splitPath(path: string): { dir: string; name: string } {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  if (cut < 0) return { dir: "", name: path };
  return { dir: path.slice(0, cut + 1), name: path.slice(cut + 1) };
}

// ----------------------------------------------------------------- screen ---

export function VaultPicker() {
  const t = useT("vault");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const go = useApp((state) => state.go);
  const queryClient = useQueryClient();

  // Every key on this screen is built in lib/queryKeys.ts. The unlock screen
  // probes the same file, and a literal spelled differently in the two places
  // is two caches of one header that disagree.
  const recents = useQuery({
    queryKey: qk.recentVaults(),
    queryFn: ipc.listRecentVaults,
  });

  const clearRecents = useMutation({
    mutationFn: ipc.clearRecentVaults,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.recentVaults() }),
  });

  // A refused "forget" leaves the row on screen, which looks exactly like a
  // click that never registered — so the failure is shown beside the button.
  const forgetRecent = useMutation({
    mutationFn: (path: string) => ipc.forgetRecentVault(path),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: qk.recentVaults() }),
  });

  const forgetFailure: IpcFailure | null =
    forgetRecent.error === null || forgetRecent.error === undefined
      ? null
      : asFailure(forgetRecent.error);

  /**
   * The panel previews whatever row has the pointer or the keyboard focus.
   * A click opens the vault, so preview cannot also be "click to select" —
   * there would be nothing left for opening.
   */
  const [previewPath, setPreviewPath] = useState<string | null>(null);
  const [dialogError, setDialogError] = useState<string | null>(null);
  // A portal-backed file browser can take a second to appear, and until it
  // does the button is the only thing on screen that could say anything.
  const [choosing, setChoosing] = useState(false);

  /**
   * The dialog plugin rejects when the platform's file browser cannot be
   * started — no portal on a bare Wayland session, for one. Left unhandled
   * that reads as a button that does nothing at all.
   */
  async function chooseFile() {
    let picked: string | string[] | null;
    setChoosing(true);
    try {
      picked = await open({
        title: t("picker.dialogTitle"),
        multiple: false,
        directory: false,
        filters: [{ name: t("picker.vaultFilter"), extensions: ["rvault"] }],
      });
    } catch {
      setDialogError(t("picker.dialogFailed"));
      return;
    } finally {
      setChoosing(false);
    }
    setDialogError(null);
    // The plugin's return type widens to an array for the multi-select case.
    const path = Array.isArray(picked) ? picked[0] : picked;
    if (typeof path === "string") go({ name: "unlock", path });
  }

  const vaults = recents.data ?? [];
  const preview = vaults.find((vault) => vault.path === previewPath) ?? vaults[0] ?? null;

  return (
    <div className={s.screen}>
      <header className={s.titlebar} data-tauri-drag-region>
        <Mark size={18} />
        <span className={s.titleText}>{tCommon("app.name")}</span>
        <span className={s.spacer} data-tauri-drag-region />
        {/* The only way into settings before a vault is open. Quiet, because
            choosing a vault is what this screen is for; reachable, because
            the language and the theme are exactly what someone changes
            first. `goBack()` from settings returns here. */}
        <button
          type="button"
          className={s.titlebarAction}
          onClick={() => go({ name: "settings" })}
          title={t("picker.settingsHint")}
          aria-label={t("picker.settings")}
        >
          <Icon name="settings" size={15} />
        </button>
      </header>

      {recents.isPending ? (
        // Rows in outline, because the alternative — a bare spinner in the
        // middle of an empty window — cannot be told apart from "no vaults".
        <div className={s.body}>
          <main className={s.main}>
            <div className={s.head}>
              <h1 className={s.h1}>{t("picker.title")}</h1>
              <p className={s.lede}>{t("picker.lede")}</p>
            </div>
            <BusyStatus label={t("picker.loading")} size={16} />
            <div className={s.rowsSkeleton}>
              <SkeletonRows count={3} height="var(--space-10)" widths={["100%"]} />
            </div>
          </main>
        </div>
      ) : recents.isError ? (
        <div className={s.centred}>
          <div className={s.calloutWidth}>
            <FailureNotice
              failure={asFailure(recents.error)}
              title={t("picker.listFailed")}
              onRetry={() => void recents.refetch()}
              retryLabel={tCommon("action.retry")}
            >
              <BusyButton
                variant="secondary"
                size="sm"
                busy={choosing}
                busyLabel={tCommon("action.opening")}
                onClick={() => void chooseFile()}
              >
                {t("picker.openFromFile")}
              </BusyButton>
              <Button
                variant="primary"
                size="sm"
                disabled={choosing}
                onClick={() => go({ name: "create" })}
              >
                {t("picker.createNew")}
              </Button>
            </FailureNotice>
            {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}
          </div>
        </div>
      ) : vaults.length === 0 ? (
        <FirstLaunch
          onCreate={() => go({ name: "create" })}
          onOpenFile={() => void chooseFile()}
          choosing={choosing}
          dialogError={dialogError}
        />
      ) : (
        <div className={s.body}>
          <main className={s.main}>
            <div className={s.head}>
              <h1 className={s.h1}>{t("picker.title")}</h1>
              <p className={s.lede}>{t("picker.lede")}</p>
            </div>

            <ul className={s.rows}>
              {vaults.map((vault) => (
                // Hover lives on the row wrapper rather than the button: a
                // disabled button swallows mouse events, and an unreachable
                // vault still has a detail panel worth reading.
                <li key={vault.path} onMouseEnter={() => setPreviewPath(vault.path)}>
                  <VaultRow
                    vault={vault}
                    selected={preview?.path === vault.path}
                    onFocusRow={() => setPreviewPath(vault.path)}
                    onOpen={() => go({ name: "unlock", path: vault.path })}
                  />
                </li>
              ))}
            </ul>

            <div className={s.actions}>
              <BusyButton
                variant="secondary"
                size="md"
                busy={choosing}
                busyLabel={tCommon("action.opening")}
                onClick={() => void chooseFile()}
              >
                <Icon name="folder" size={15} />
                {t("picker.openFromFile")}
              </BusyButton>
              <Button
                variant="secondary"
                size="md"
                disabled={choosing}
                onClick={() => go({ name: "create" })}
              >
                <Icon name="plus" size={15} />
                {t("picker.createNew")}
              </Button>
            </div>

            {/* Beside the button that opens it, not in a corner of the window. */}
            {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}

            <div className={s.spacer} />

            <footer className={s.foot}>
              <Icon name="alert" size={12} />
              <span>
                {t("picker.recentsNote")}{" "}
                <button
                  type="button"
                  className={s.link}
                  disabled={clearRecents.isPending}
                  onClick={() => clearRecents.mutate()}
                >
                  {clearRecents.isPending ? t("picker.clearing") : t("picker.clearList")}
                </button>
              </span>
            </footer>

            {clearRecents.isError && (
              <div className={s.footNotice}>
                <FailureNotice
                  failure={asFailure(clearRecents.error)}
                  title={t("picker.clearFailed")}
                  onRetry={() => clearRecents.mutate()}
                  retryLabel={tCommon("action.retry")}
                />
              </div>
            )}
          </main>

          <aside className={s.aside}>
            {preview === null ? null : preview.reachable ? (
              <VaultDetail
                vault={preview}
                locale={locale}
                onForget={() => forgetRecent.mutate(preview.path)}
                forgetting={forgetRecent.isPending}
                forgetFailure={forgetFailure}
              />
            ) : (
              <UnreachableDetail
                vault={preview}
                locale={locale}
                onForget={() => forgetRecent.mutate(preview.path)}
                forgetting={forgetRecent.isPending}
                forgetFailure={forgetFailure}
              />
            )}
          </aside>
        </div>
      )}
    </div>
  );
}

// -------------------------------------------------------------------- row ---

function VaultRow({
  vault,
  selected,
  onFocusRow,
  onOpen,
}: {
  vault: RecentVault;
  selected: boolean;
  onFocusRow: () => void;
  onOpen: () => void;
}) {
  const t = useT("vault");
  const { code: locale } = useLocale();
  const classes = [s.row, selected ? s.rowSelected : "", vault.reachable ? "" : s.rowDisabled]
    .filter(Boolean)
    .join(" ");

  return (
    <button
      type="button"
      className={classes}
      // An unreachable vault stays visible and disabled with its reason shown.
      // Hiding it would read as data loss.
      disabled={!vault.reachable}
      onClick={onOpen}
      onFocus={onFocusRow}
    >
      <Icon name={vault.reachable ? "file" : "alert"} size={19} />

      {/* The label is the user's own name for the vault and the path is a file
          path. Both are isolated so that neither can reorder the row around
          it — see src/i18n/bidi.ts. */}
      <span className={s.rowText}>
        <span className={s.rowName}>{isolate(vault.label)}</span>
        <span className={s.rowPath}>{isolateLtr(vault.path)}</span>
      </span>

      <span className={s.spacer} />

      {vault.reachable ? (
        <span className={s.rowRight}>
          <span className={s.slots}>
            {vault.slots.map((slot) => (
              <span
                key={slot}
                className={slot === "fido2" ? s.slotBadgeStrong : s.slotBadge}
                title={slotBadgeLabel(t, slot)}
              >
                <Icon name={SLOT_ICONS[slot]} size={11} />
                <span className="visually-hidden">{slotBadgeLabel(t, slot)}</span>
              </span>
            ))}
          </span>
          <span className={s.rowMeta}>
            {vault.lastOpened === null
              ? t("picker.neverOpened")
              : formatRelativeTime(locale, toMillis(vault.lastOpened))}
          </span>
        </span>
      ) : (
        <span className={s.rowUnreachable}>
          <Icon name="alert" size={12} />
          {vault.unreachableReason ?? t("detail.unreachableTitle")}
        </span>
      )}
    </button>
  );
}

// ----------------------------------------------------------------- detail ---

/**
 * The reason a control cannot be pressed, and the failure of the one that was.
 * Rendered together because they occupy the same slot beneath the button.
 */
function ForgetButton({
  onForget,
  forgetting,
  forgetFailure,
}: {
  onForget: () => void;
  forgetting: boolean;
  forgetFailure: IpcFailure | null;
}) {
  const t = useT("vault");
  const tCommon = useT("common");

  return (
    <>
      <BusyButton
        variant="ghost"
        size="sm"
        busy={forgetting}
        busyLabel={t("picker.forgetting")}
        onClick={onForget}
        title={forgetting ? t("picker.forgetting") : t("picker.forget")}
      >
        {t("picker.forget")}
      </BusyButton>
      {forgetFailure !== null && (
        <div className={s.asideNotice}>
          <FailureNotice
            failure={forgetFailure}
            title={t("picker.forgetFailed")}
            onRetry={onForget}
            retryLabel={tCommon("action.retry")}
          />
        </div>
      )}
    </>
  );
}

function VaultDetail({
  vault,
  locale,
  onForget,
  forgetting,
  forgetFailure,
}: {
  vault: RecentVault;
  locale: string;
  onForget: () => void;
  forgetting: boolean;
  forgetFailure: IpcFailure | null;
}) {
  const t = useT("vault");
  const tCommon = useT("common");

  const probe = useQuery({
    queryKey: qk.vaultProbe(vault.path),
    queryFn: () => ipc.probeVault(vault.path),
  });

  return (
    <>
      <div className={s.asideHead}>{isolate(vault.label)}</div>

      {probe.isPending ? (
        // The panel is already the width of the finished thing; leaving it
        // blank makes hovering a row look like it did nothing.
        <div className={s.asideLoading}>
          <BusyStatus label={t("probe.reading")} size={14} />
          <div className={s.asideSkeleton}>
            <SkeletonRows count={4} height="var(--space-6)" widths={["100%"]} />
          </div>
        </div>
      ) : probe.isError ? (
        <FailureNotice
          failure={asFailure(probe.error)}
          title={t("detail.probeFailed")}
          onRetry={() => void probe.refetch()}
          retryLabel={tCommon("action.retry")}
        />
      ) : (
        <>
          <dl className={s.stats}>
            <div className={s.stat}>
              <dt className={s.statLabel}>{t("detail.connections")}</dt>
              <dd className={s.statValue}>{t("detail.unknownValue")}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{t("detail.credentials")}</dt>
              <dd className={s.statValue}>{t("detail.unknownValue")}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{t("detail.format")}</dt>
              <dd className={s.statValue}>{formatLabel(probe.data.formatVersion)}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{t("detail.size")}</dt>
              <dd className={s.statValue}>{formatBytes(locale, probe.data.sizeBytes)}</dd>
            </div>
          </dl>
          <p className={s.asideNote}>{t("detail.sealedCounts")}</p>

          <hr className={s.rule} />

          <div className={s.asideHead}>{t("detail.backups")}</div>
          {probe.data.backups.length === 0 ? (
            <p className={s.asideNote}>{t("detail.noBackups")}</p>
          ) : (
            <ul className={s.backups}>
              {probe.data.backups.map((backup, index) => (
                <li key={backup.path} className={s.backup}>
                  <span className={index === 0 ? s.dotCurrent : s.dot} />
                  <span className={index === 0 ? s.backupStampCurrent : s.backupStamp}>
                    {formatStamp(locale, backup.modifiedAt)}
                  </span>
                  <span className={s.backupSize}>{formatBytes(locale, backup.sizeBytes)}</span>
                </li>
              ))}
            </ul>
          )}

          {/* The warning itself is the core's sentence; only its heading is ours. */}
          {probe.data.syncWarning !== null ? (
            <>
              <hr className={s.rule} />
              <Callout tone="warning" title={t("detail.syncTitle")}>
                <p className={s.calloutBody}>{probe.data.syncWarning}</p>
              </Callout>
            </>
          ) : null}
        </>
      )}

      <div className={s.spacer} />
      <ForgetButton onForget={onForget} forgetting={forgetting} forgetFailure={forgetFailure} />
      <div className={s.asideFoot}>{BUILD_LINE}</div>
    </>
  );
}

function UnreachableDetail({
  vault,
  locale,
  onForget,
  forgetting,
  forgetFailure,
}: {
  vault: RecentVault;
  locale: string;
  onForget: () => void;
  forgetting: boolean;
  forgetFailure: IpcFailure | null;
}) {
  const t = useT("vault");

  return (
    <>
      <div className={s.asideHead}>{isolate(vault.label)}</div>
      <Callout tone="warning" title={t("detail.unreachableTitle")}>
        <p className={s.calloutBody}>{vault.unreachableReason ?? isolateLtr(vault.path)}</p>
      </Callout>
      <dl className={s.stats}>
        <div className={s.stat}>
          <dt className={s.statLabel}>{t("detail.size")}</dt>
          <dd className={s.statValue}>
            {vault.sizeBytes === null
              ? t("detail.unknownValue")
              : formatBytes(locale, vault.sizeBytes)}
          </dd>
        </div>
      </dl>
      {vault.syncWarning !== null ? (
        <Callout tone="warning" title={t("detail.syncTitle")}>
          <p className={s.calloutBody}>{vault.syncWarning}</p>
        </Callout>
      ) : null}
      <div className={s.spacer} />
      <ForgetButton onForget={onForget} forgetting={forgetting} forgetFailure={forgetFailure} />
      <div className={s.asideFoot}>{BUILD_LINE}</div>
    </>
  );
}

// ----------------------------------------------------------- first launch ---

function FirstLaunch({
  onCreate,
  onOpenFile,
  choosing,
  dialogError,
}: {
  onCreate: () => void;
  onOpenFile: () => void;
  choosing: boolean;
  dialogError: string | null;
}) {
  const t = useT("vault");
  const tCommon = useT("common");

  return (
    <div className={s.first}>
      <div className={s.firstHead}>
        <Mark size={44} />
        <h1 className={s.firstTitle}>{t("firstRun.title")}</h1>
        <p className={s.firstLede}>{t("firstRun.lede")}</p>
      </div>

      <div className={s.doors}>
        {/* Import is the brighter door: most people arriving here already keep
            their connections somewhere else. */}
        <button type="button" className={`${s.door} ${s.doorPrimary}`} onClick={onCreate}>
          <Icon name="download" size={20} />
          <span className={s.doorTitle}>{t("firstRun.importTitle")}</span>
          <span className={s.doorHelp}>{t("firstRun.importHelp")}</span>
        </button>
        <button type="button" className={s.door} onClick={onCreate}>
          <Icon name="plus" size={20} />
          <span className={s.doorTitle}>{t("firstRun.emptyTitle")}</span>
          <span className={s.doorHelp}>{t("firstRun.emptyHelp")}</span>
        </button>
      </div>

      <div className={s.firstFoot}>
        <Badge tone="neutral" mono>
          {BUILD_LINE}
        </Badge>
        <button type="button" className={s.link} disabled={choosing} onClick={onOpenFile}>
          {choosing ? tCommon("action.opening") : t("picker.openExisting")}
        </button>
      </div>

      {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}
    </div>
  );
}
