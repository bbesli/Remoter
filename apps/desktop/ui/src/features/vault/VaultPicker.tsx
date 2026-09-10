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

import { Badge } from "@/components/Badge";
import { BusyButton, BusyStatus, SkeletonRows } from "@/components/Busy";
import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { Mark } from "@/components/Mark";
import { asFailure, ipc } from "@/lib/ipc";
import type { IpcFailure, RecentVault, SlotKind } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import s from "./VaultPicker.module.css";

/**
 * v0.1 ships English only. Keeping the strings in one block per file means
 * extraction into `locales/en` later is mechanical rather than archaeological.
 */
const TEXT = {
  appName: "Remoter",
  title: "Open a vault",
  lede: "Nothing is decrypted until you unlock one.",

  loading: "Reading the list of recent vaults…",
  listFailed: "The list of recent vaults could not be read.",
  retry: "Try again",

  openFromFile: "Open from file…",
  /* Short, because the idle label reserves room for it. The tooltip on the
     busy button carries the same words. */
  choosing: "Opening…",
  createNew: "Create a new vault",
  dialogTitle: "Open a Remoter vault",
  vaultFilter: "Remoter vault",
  dialogFailed:
    "The system file browser did not open, so no vault could be chosen that way. A vault you have opened before is still listed here.",

  recentsNote: "Recent vault paths are stored on this machine only.",
  clearList: "Clear the list",
  clearing: "Clearing…",
  clearFailed: "The list of recent vaults was not cleared.",
  forget: "Forget this vault",
  forgetting: "Forgetting…",
  forgetFailed: "This vault was not removed from the list.",

  probing: "Reading the vault header…",
  probeFailed: "This vault's header could not be read.",

  connections: "Connections",
  credentials: "Credentials",
  format: "Format",
  size: "Size",
  sealedCounts:
    "Connection and credential counts are inside the encrypted body. They appear once the vault is open.",
  formatName: (version: number) => `rvault v${version}`,
  backups: "Rolling backups",
  noBackups: "No backups have been written beside this file yet.",
  syncTitle: "In a synced folder",
  unreachableTitle: "This vault cannot be reached",
  neverOpened: "never opened",
  unknown: "—",

  firstTitle: "Remoter needs a vault before it can do anything",
  firstLede:
    "A vault is one encrypted file holding your connections and their credentials. You can have several — one for work, one for a client — and they open on any platform.",
  importTitle: "Bring across what I have",
  importHelp:
    "Creates a vault first. The import wizard for mRemoteNG, Royal TS, PuTTY and ~/.ssh/config arrives in a later version, so for now this is the same four steps as starting empty.",
  emptyTitle: "Start empty",
  emptyHelp:
    "Four steps: where the file lives, a master password, an optional key file, and your recovery key.",
  openExisting: "Open an existing vault instead",

  slotLabels: {
    password: "Master password slot",
    recovery: "Recovery key slot",
    fido2: "Security key slot",
    keychain: "Saved on this device",
  } satisfies Record<SlotKind, string>,

  settings: "Settings",
  /* Named for what someone would want here: the language and the theme are the
     two things worth changing before a vault is ever opened. */
  settingsHint: "Settings — language, theme and shortcuts",

  version: "v0.1.0-dev · GPL-3.0",
} as const;

const SLOT_ICONS = {
  password: "lock",
  recovery: "key",
  fido2: "usb",
  keychain: "shield",
} as const satisfies Record<SlotKind, "lock" | "key" | "usb" | "shield">;

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

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

const RELATIVE_UNITS: ReadonlyArray<readonly [Intl.RelativeTimeFormatUnit, number]> = [
  ["year", 31_557_600_000],
  ["month", 2_629_800_000],
  ["week", 604_800_000],
  ["day", 86_400_000],
  ["hour", 3_600_000],
  ["minute", 60_000],
  ["second", 1_000],
];

/** "2 minutes ago", "yesterday" — the wording the design asks for. */
export function formatRelative(stamp: number | null): string {
  if (stamp === null) return TEXT.neverOpened;
  const delta = toMillis(stamp) - Date.now();
  for (const [unit, size] of RELATIVE_UNITS) {
    if (Math.abs(delta) >= size) return RELATIVE.format(Math.round(delta / size), unit);
  }
  return RELATIVE.format(0, "second");
}

const STAMP = new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" });

export function formatStamp(stamp: number): string {
  return STAMP.format(new Date(toMillis(stamp)));
}

const BYTE_UNITS = ["B", "KB", "MB", "GB"] as const;

export function formatBytes(bytes: number | null): string {
  if (bytes === null) return TEXT.unknown;
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < BYTE_UNITS.length - 1) {
    value /= 1024;
    unit += 1;
  }
  const rounded = unit === 0 ? Math.round(value) : Math.round(value * 10) / 10;
  return `${rounded} ${BYTE_UNITS[unit] ?? BYTE_UNITS[0]}`;
}

/** Splits a path so the file name can carry the weight and the directory recedes. */
export function splitPath(path: string): { dir: string; name: string } {
  const cut = Math.max(path.lastIndexOf("/"), path.lastIndexOf("\\"));
  if (cut < 0) return { dir: "", name: path };
  return { dir: path.slice(0, cut + 1), name: path.slice(cut + 1) };
}

// ----------------------------------------------------------------- screen ---

export function VaultPicker() {
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
        title: TEXT.dialogTitle,
        multiple: false,
        directory: false,
        filters: [{ name: TEXT.vaultFilter, extensions: ["rvault"] }],
      });
    } catch {
      setDialogError(TEXT.dialogFailed);
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
        <span className={s.titleText}>{TEXT.appName}</span>
        <span className={s.spacer} data-tauri-drag-region />
        {/* The only way into settings before a vault is open. Quiet, because
            choosing a vault is what this screen is for; reachable, because
            the language and the theme are exactly what someone changes
            first. `goBack()` from settings returns here. */}
        <button
          type="button"
          className={s.titlebarAction}
          onClick={() => go({ name: "settings" })}
          title={TEXT.settingsHint}
          aria-label={TEXT.settings}
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
              <h1 className={s.h1}>{TEXT.title}</h1>
              <p className={s.lede}>{TEXT.lede}</p>
            </div>
            <BusyStatus label={TEXT.loading} size={16} />
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
              title={TEXT.listFailed}
              onRetry={() => void recents.refetch()}
              retryLabel={TEXT.retry}
            >
              <BusyButton
                variant="secondary"
                size="sm"
                busy={choosing}
                busyLabel={TEXT.choosing}
                onClick={() => void chooseFile()}
              >
                {TEXT.openFromFile}
              </BusyButton>
              <Button
                variant="primary"
                size="sm"
                disabled={choosing}
                onClick={() => go({ name: "create" })}
              >
                {TEXT.createNew}
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
              <h1 className={s.h1}>{TEXT.title}</h1>
              <p className={s.lede}>{TEXT.lede}</p>
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
                busyLabel={TEXT.choosing}
                onClick={() => void chooseFile()}
              >
                <Icon name="folder" size={15} />
                {TEXT.openFromFile}
              </BusyButton>
              <Button
                variant="secondary"
                size="md"
                disabled={choosing}
                onClick={() => go({ name: "create" })}
              >
                <Icon name="plus" size={15} />
                {TEXT.createNew}
              </Button>
            </div>

            {/* Beside the button that opens it, not in a corner of the window. */}
            {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}

            <div className={s.spacer} />

            <footer className={s.foot}>
              <Icon name="alert" size={12} />
              <span>
                {TEXT.recentsNote}{" "}
                <button
                  type="button"
                  className={s.link}
                  disabled={clearRecents.isPending}
                  onClick={() => clearRecents.mutate()}
                >
                  {clearRecents.isPending ? TEXT.clearing : TEXT.clearList}
                </button>
              </span>
            </footer>

            {clearRecents.isError && (
              <div className={s.footNotice}>
                <FailureNotice
                  failure={asFailure(clearRecents.error)}
                  title={TEXT.clearFailed}
                  onRetry={() => clearRecents.mutate()}
                  retryLabel={TEXT.retry}
                />
              </div>
            )}
          </main>

          <aside className={s.aside}>
            {preview === null ? null : preview.reachable ? (
              <VaultDetail
                vault={preview}
                onForget={() => forgetRecent.mutate(preview.path)}
                forgetting={forgetRecent.isPending}
                forgetFailure={forgetFailure}
              />
            ) : (
              <UnreachableDetail
                vault={preview}
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

      <span className={s.rowText}>
        <span className={s.rowName}>{vault.label}</span>
        <span className={s.rowPath}>{vault.path}</span>
      </span>

      <span className={s.spacer} />

      {vault.reachable ? (
        <span className={s.rowRight}>
          <span className={s.slots}>
            {vault.slots.map((slot) => (
              <span
                key={slot}
                className={slot === "fido2" ? s.slotBadgeStrong : s.slotBadge}
                title={TEXT.slotLabels[slot]}
              >
                <Icon name={SLOT_ICONS[slot]} size={11} />
                <span className="visually-hidden">{TEXT.slotLabels[slot]}</span>
              </span>
            ))}
          </span>
          <span className={s.rowMeta}>{formatRelative(vault.lastOpened)}</span>
        </span>
      ) : (
        <span className={s.rowUnreachable}>
          <Icon name="alert" size={12} />
          {vault.unreachableReason ?? TEXT.unreachableTitle}
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
  return (
    <>
      <BusyButton
        variant="ghost"
        size="sm"
        busy={forgetting}
        busyLabel={TEXT.forgetting}
        onClick={onForget}
        title={forgetting ? TEXT.forgetting : TEXT.forget}
      >
        {TEXT.forget}
      </BusyButton>
      {forgetFailure !== null && (
        <div className={s.asideNotice}>
          <FailureNotice
            failure={forgetFailure}
            title={TEXT.forgetFailed}
            onRetry={onForget}
            retryLabel={TEXT.retry}
          />
        </div>
      )}
    </>
  );
}

function VaultDetail({
  vault,
  onForget,
  forgetting,
  forgetFailure,
}: {
  vault: RecentVault;
  onForget: () => void;
  forgetting: boolean;
  forgetFailure: IpcFailure | null;
}) {
  const probe = useQuery({
    queryKey: qk.vaultProbe(vault.path),
    queryFn: () => ipc.probeVault(vault.path),
  });

  return (
    <>
      <div className={s.asideHead}>{vault.label}</div>

      {probe.isPending ? (
        // The panel is already the width of the finished thing; leaving it
        // blank makes hovering a row look like it did nothing.
        <div className={s.asideLoading}>
          <BusyStatus label={TEXT.probing} size={14} />
          <div className={s.asideSkeleton}>
            <SkeletonRows count={4} height="var(--space-6)" widths={["100%"]} />
          </div>
        </div>
      ) : probe.isError ? (
        <FailureNotice
          failure={asFailure(probe.error)}
          title={TEXT.probeFailed}
          onRetry={() => void probe.refetch()}
          retryLabel={TEXT.retry}
        />
      ) : (
        <>
          <dl className={s.stats}>
            <div className={s.stat}>
              <dt className={s.statLabel}>{TEXT.connections}</dt>
              <dd className={s.statValue}>{TEXT.unknown}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{TEXT.credentials}</dt>
              <dd className={s.statValue}>{TEXT.unknown}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{TEXT.format}</dt>
              <dd className={s.statValue}>{TEXT.formatName(probe.data.formatVersion)}</dd>
            </div>
            <div className={s.stat}>
              <dt className={s.statLabel}>{TEXT.size}</dt>
              <dd className={s.statValue}>{formatBytes(probe.data.sizeBytes)}</dd>
            </div>
          </dl>
          <p className={s.asideNote}>{TEXT.sealedCounts}</p>

          <hr className={s.rule} />

          <div className={s.asideHead}>{TEXT.backups}</div>
          {probe.data.backups.length === 0 ? (
            <p className={s.asideNote}>{TEXT.noBackups}</p>
          ) : (
            <ul className={s.backups}>
              {probe.data.backups.map((backup, index) => (
                <li key={backup.path} className={s.backup}>
                  <span className={index === 0 ? s.dotCurrent : s.dot} />
                  <span className={index === 0 ? s.backupStampCurrent : s.backupStamp}>
                    {formatStamp(backup.modifiedAt)}
                  </span>
                  <span className={s.backupSize}>{formatBytes(backup.sizeBytes)}</span>
                </li>
              ))}
            </ul>
          )}

          {probe.data.syncWarning !== null ? (
            <>
              <hr className={s.rule} />
              <Callout tone="warning" title={TEXT.syncTitle}>
                <p className={s.calloutBody}>{probe.data.syncWarning}</p>
              </Callout>
            </>
          ) : null}
        </>
      )}

      <div className={s.spacer} />
      <ForgetButton onForget={onForget} forgetting={forgetting} forgetFailure={forgetFailure} />
      <div className={s.asideFoot}>{TEXT.version}</div>
    </>
  );
}

function UnreachableDetail({
  vault,
  onForget,
  forgetting,
  forgetFailure,
}: {
  vault: RecentVault;
  onForget: () => void;
  forgetting: boolean;
  forgetFailure: IpcFailure | null;
}) {
  return (
    <>
      <div className={s.asideHead}>{vault.label}</div>
      <Callout tone="warning" title={TEXT.unreachableTitle}>
        <p className={s.calloutBody}>{vault.unreachableReason ?? vault.path}</p>
      </Callout>
      <dl className={s.stats}>
        <div className={s.stat}>
          <dt className={s.statLabel}>{TEXT.size}</dt>
          <dd className={s.statValue}>{formatBytes(vault.sizeBytes)}</dd>
        </div>
      </dl>
      {vault.syncWarning !== null ? (
        <Callout tone="warning" title={TEXT.syncTitle}>
          <p className={s.calloutBody}>{vault.syncWarning}</p>
        </Callout>
      ) : null}
      <div className={s.spacer} />
      <ForgetButton onForget={onForget} forgetting={forgetting} forgetFailure={forgetFailure} />
      <div className={s.asideFoot}>{TEXT.version}</div>
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
  return (
    <div className={s.first}>
      <div className={s.firstHead}>
        <Mark size={44} />
        <h1 className={s.firstTitle}>{TEXT.firstTitle}</h1>
        <p className={s.firstLede}>{TEXT.firstLede}</p>
      </div>

      <div className={s.doors}>
        {/* Import is the brighter door: most people arriving here already keep
            their connections somewhere else. */}
        <button type="button" className={`${s.door} ${s.doorPrimary}`} onClick={onCreate}>
          <Icon name="download" size={20} />
          <span className={s.doorTitle}>{TEXT.importTitle}</span>
          <span className={s.doorHelp}>{TEXT.importHelp}</span>
        </button>
        <button type="button" className={s.door} onClick={onCreate}>
          <Icon name="plus" size={20} />
          <span className={s.doorTitle}>{TEXT.emptyTitle}</span>
          <span className={s.doorHelp}>{TEXT.emptyHelp}</span>
        </button>
      </div>

      <div className={s.firstFoot}>
        <Badge tone="neutral" mono>
          {TEXT.version}
        </Badge>
        <button type="button" className={s.link} disabled={choosing} onClick={onOpenFile}>
          {choosing ? TEXT.choosing : TEXT.openExisting}
        </button>
      </div>

      {dialogError !== null && <p className={s.dialogError}>{dialogError}</p>}
    </div>
  );
}
