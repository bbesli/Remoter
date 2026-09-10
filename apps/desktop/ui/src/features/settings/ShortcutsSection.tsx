/**
 * The keyboard map: what is bound, where it fires, and how to change it.
 *
 * The table used to be a hand-written copy of the one in
 * `docs/features/connections.md`. Nine of the thirteen rows named keys nothing
 * in the application had ever bound, and the screen said "editing is not
 * available" while the documentation said the map was user-editable. Both are
 * fixed here, and the fix is structural rather than editorial: the rows are
 * rendered from `@/hooks/keyboard`, which is the same catalogue the one
 * window-level listener dispatches. A row cannot describe a binding the
 * application does not have, because the row and the binding are one record.
 *
 * What is still not ours to give is said in the row rather than left to be
 * discovered:
 *
 *  - an action nothing in this build implements says it is not bound;
 *  - an action the core's settings file has no entry for says its binding is
 *    fixed, and its key cap is not offered as a control;
 *  - a combination the desktop takes first, or that the remote host needs,
 *    says so beside the keys.
 *
 * A control that cannot do what it says must not be drawn as though it can.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { BusyStatus } from "@/components/Busy";
import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { TextInput } from "@/components/TextInput";
import { asFailure, ipc } from "@/lib/ipc";
import type { AppSettings as AppSettingsDto, AppSettingsPatch } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import {
  DEFAULT_TERMINAL_PREFIX,
  SHORTCUT_ACTIONS,
  TERMINAL_PREFIX_CHOICES,
  acceleratorCaps,
  acceleratorFromEvent,
  acceleratorLabel,
  checkBinding,
  isModifierKey,
  normalisePrefix,
  resolveShortcuts,
  withPrefix,
  type BindingRefusal,
  type ResolvedShortcut,
  type ShortcutOverrides,
} from "@/hooks/keyboard";

import { SettingsSection } from "./SettingsSection";
import s from "./ShortcutsSection.module.css";

const TEXT = {
  title: "Shortcuts",
  description:
    "Every binding below is what the application actually listens for. A focused terminal must receive almost every keystroke, so application shortcuts inside a session go through a prefix.",

  loading: "Reading your shortcut map…",
  loadFailed: "Your shortcut map could not be read.",
  retry: "Try again",
  loadFallback:
    "These are the shipped defaults. Any binding you changed is not shown, and cannot be changed here until the settings file can be read.",

  prefixTitle: "Terminal prefix",
  prefixBody:
    "Ctrl+C, Ctrl+D and Alt+F belong to the remote host, so Remoter does not take them. Inside a session, hold the prefix as well.",
  prefixLegend: "The prefix held with an application shortcut inside a session",
  prefixSaving: "Saving the prefix…",
  prefixFailed: "The prefix was not changed.",

  searchLabel: "Search shortcuts",
  searchPlaceholder: "Filter by action or key",

  caption: "Keyboard shortcuts, with what each one can and cannot reach",
  colAction: "Action",
  colShortcut: "Shortcut",
  colScope: "Where it works",

  scopeUniversal: "Everywhere",
  scopeApplication: "Prefixed in a session",
  scopeContext: "Only where it is typed",
  scopeNowhere: "Nowhere",

  inSession: (keys: string) => `Inside a focused session: ${keys}`,

  edit: (action: string, keys: string) => `Change the shortcut for ${action}, currently ${keys}`,
  capturing: "Press the keys…",
  capturingHint: "Press the combination you want, or Esc to cancel.",
  fixed: (action: string) => `The shortcut for ${action} cannot be changed`,
  saving: "Saving…",

  reset: (action: string) => `Reset ${action} to its shipped keys`,
  resetAll: "Reset every shortcut",
  resetAllBusy: "Resetting…",
  resetAllNone: "Every editable shortcut is already at its shipped default.",
  saveFailed: "The shortcut was not saved.",

  count: (shown: number, total: number) => `Showing ${shown} of ${total} shortcuts.`,
  empty: "No shortcut matches that.",

  conflictDuplicate: (titles: string[]) =>
    `Already held by ${titles.join(", ")}. Only one of them can fire, so change one of the two.`,
  conflictReservedUniversal:
    "The remote shell needs these keys, so a focused session keeps them and this shortcut never fires there.",
  conflictReservedApplication:
    "These keys belong to the remote shell and to copy-and-paste. The prefix keeps them clear inside a session, but outside one Remoter takes them.",
  conflictDesktop:
    "Some desktops take this combination for their own window switcher and win. Where that happens the press never reaches Remoter.",

  refusedInvalid: "That is not a combination Remoter can bind.",
  refusedReserved: (keys: string) =>
    `${keys} belongs to the remote host: a focused terminal has to receive it, so binding it here would stop it reaching the shell.`,
  refusedDuplicate: (keys: string, title: string) =>
    `${keys} is already held by ${title}. Nothing was changed — free it there first, or pick another combination.`,
  refusedUnknown: "This build does not carry that action.",
} as const;

/** How each prefix choice is written on its own button. */
const PREFIX_LABELS: Readonly<Record<string, string>> = {
  "ctrl+alt": "Ctrl + Alt",
  "ctrl+shift": "Ctrl + Shift",
  "alt+shift": "Alt + Shift",
};

/** No overrides, as one object, so an unchanged read keeps its identity. */
const NO_OVERRIDES: ShortcutOverrides = {};

/** What this screen is currently writing, so exactly one control says so. */
type SaveTarget =
  | { kind: "binding"; actionId: string }
  | { kind: "prefix" }
  | { kind: "reset-all" };

interface SaveVariables {
  target: SaveTarget;
  patch: AppSettingsPatch;
}

/**
 * Case folding pinned to one locale.
 *
 * `toLowerCase` is locale-sensitive in the user's environment — in Turkish "I"
 * folds to "ı", so a search for "Ctrl" would stop matching. The bindings are
 * ASCII, so folding them in a fixed locale is both correct and stable.
 */
function fold(value: string): string {
  return value.toLocaleLowerCase("en-US");
}

/** The one sentence a row's scope cell carries. */
function scopeLabel(entry: ResolvedShortcut): string {
  switch (entry.action.owner) {
    case "none":
      return TEXT.scopeNowhere;
    case "context":
      return TEXT.scopeContext;
    default:
      return entry.action.scope === "universal" ? TEXT.scopeUniversal : TEXT.scopeApplication;
  }
}

/** Everything the row must say beyond its keys, worst first. */
function rowNotes(entry: ResolvedShortcut): string[] {
  const notes: string[] = [];
  const conflict = entry.conflict;

  if (conflict !== null) {
    if (conflict.kind === "duplicate") notes.push(TEXT.conflictDuplicate(conflict.withTitles));
    else if (conflict.kind === "terminal-reserved") {
      notes.push(
        entry.action.scope === "universal"
          ? TEXT.conflictReservedUniversal
          : TEXT.conflictReservedApplication,
      );
    } else notes.push(TEXT.conflictDesktop);
  }

  if (entry.action.reachNote !== null) notes.push(entry.action.reachNote);
  if (!entry.action.editable && entry.action.unrebindableReason !== null) {
    notes.push(entry.action.unrebindableReason);
  }
  return notes;
}

/** The refusal, in the user's terms. */
function describeRefusal(refusal: BindingRefusal): string {
  switch (refusal.kind) {
    case "invalid":
      return TEXT.refusedInvalid;
    case "terminal-reserved":
      return TEXT.refusedReserved(acceleratorLabel(refusal.accelerator));
    case "duplicate":
      return TEXT.refusedDuplicate(acceleratorLabel(refusal.accelerator), refusal.withTitle);
    case "not-editable":
      return refusal.reason;
    case "unknown-action":
      return TEXT.refusedUnknown;
  }
}

function haystack(entry: ResolvedShortcut): string {
  return fold(
    [
      entry.action.title,
      acceleratorLabel(entry.accelerator, entry.action.seriesLen),
      scopeLabel(entry),
      ...rowNotes(entry),
    ]
      .join(" ")
      .replace(/\+/g, " "),
  );
}

export function ShortcutsSection() {
  const queryClient = useQueryClient();
  const [query, setQuery] = useState("");

  /** The action whose keys are being captured, or `null`. */
  const [capturing, setCapturing] = useState<string | null>(null);
  /** A binding this screen refused before sending it anywhere. */
  const [refused, setRefused] = useState<{ actionId: string; message: string } | null>(null);

  const settings = useQuery({ queryKey: qk.settings(), queryFn: ipc.getSettings });

  const save = useMutation<AppSettingsDto, unknown, SaveVariables>({
    mutationFn: (variables) => ipc.setSettings(variables.patch),
    // Straight into the cache the listener reads, so a saved binding is live
    // in the same tick rather than after a restart.
    onSuccess: (next) => queryClient.setQueryData(qk.settings(), next),
  });

  const overrides: ShortcutOverrides = settings.data?.shortcuts ?? NO_OVERRIDES;
  const prefix =
    normalisePrefix(settings.data?.terminalPrefix ?? "") ?? DEFAULT_TERMINAL_PREFIX;

  const resolved = useMemo(() => resolveShortcuts(overrides), [overrides]);

  const matches = useMemo(() => {
    const needle = fold(query.trim());
    if (needle === "") return resolved;
    return resolved.filter((entry) => haystack(entry).includes(needle));
  }, [query, resolved]);

  const customisedCount = resolved.filter((entry) => entry.customised).length;

  const commit = useCallback(
    (actionId: string, chord: string) => {
      setCapturing(null);
      const refusal = checkBinding(actionId, chord, overrides);
      if (refusal !== null) {
        setRefused({ actionId, message: describeRefusal(refusal) });
        return;
      }
      setRefused(null);
      save.mutate({
        target: { kind: "binding", actionId },
        patch: { shortcuts: { [actionId]: chord } },
      });
    },
    [overrides, save],
  );

  /*
   * While a capture is on, this screen owns the keyboard completely.
   *
   * Capture phase on the window, so Tab does not move focus out of the button,
   * Escape does not leave the settings screen through the listener in
   * `AppSettings`, and a combination that is bound elsewhere is recorded
   * rather than performed.
   */
  useEffect(() => {
    if (capturing === null) return;

    const onKey = (event: KeyboardEvent) => {
      event.preventDefault();
      event.stopPropagation();
      // Still holding modifiers down; there is no key to bind yet.
      if (isModifierKey(event.key)) return;
      if (event.key === "Escape") {
        setCapturing(null);
        return;
      }
      const chord = acceleratorFromEvent(event);
      if (chord === null) return;
      commit(capturing, chord);
    };

    // Clicking away ends the capture. A screen that quietly stayed armed would
    // bind the next keystroke the user meant for something else.
    const onPointer = () => setCapturing(null);

    window.addEventListener("keydown", onKey, true);
    window.addEventListener("pointerdown", onPointer, true);
    return () => {
      window.removeEventListener("keydown", onKey, true);
      window.removeEventListener("pointerdown", onPointer, true);
    };
  }, [capturing, commit]);

  const savingTarget = save.isPending ? (save.variables?.target ?? null) : null;
  const saveFailure = save.error === null || save.error === undefined ? null : asFailure(save.error);
  const failedTarget = saveFailure === null ? null : (save.variables?.target ?? null);

  const onResetAll = () => {
    setRefused(null);
    const shortcuts: Record<string, string | null> = {};
    // A null accelerator is the core's "restore the shipped default"; only the
    // ids it stores may appear, or it refuses the whole patch.
    for (const action of SHORTCUT_ACTIONS) {
      if (action.editable) shortcuts[action.id] = null;
    }
    save.mutate({ target: { kind: "reset-all" }, patch: { shortcuts } });
  };

  const onResetOne = (actionId: string) => {
    setRefused(null);
    save.mutate({
      target: { kind: "binding", actionId },
      patch: { shortcuts: { [actionId]: null } },
    });
  };

  const onPrefix = (value: string) => {
    setRefused(null);
    save.mutate({ target: { kind: "prefix" }, patch: { terminalPrefix: value } });
  };

  /*
   * Nothing is drawn until the map has been read.
   *
   * Rendering the shipped defaults first and correcting them a moment later
   * would show every user who has rebound anything the wrong keys — briefly,
   * and with no sign that they were provisional.
   */
  if (settings.isPending) {
    return (
      <SettingsSection title={TEXT.title} description={TEXT.description}>
        <BusyStatus label={TEXT.loading} size={16} />
      </SettingsSection>
    );
  }

  return (
    <SettingsSection title={TEXT.title} description={TEXT.description}>

      {/*
       * A failed read is said out loud, and the table below still renders the
       * shipped defaults — with a line saying that is what they are. Showing
       * defaults silently would be the screen quietly losing the user's map.
       */}
      {settings.isError && (
        <>
          <FailureNotice
            failure={asFailure(settings.error)}
            title={TEXT.loadFailed}
            onRetry={() => void settings.refetch()}
            retryLabel={TEXT.retry}
          />
          <p className={s.note}>{TEXT.loadFallback}</p>
        </>
      )}

      <div className={s.prefix}>
        <div className={s.prefixText}>
          <span className={s.prefixTitle}>{TEXT.prefixTitle}</span>
          <span className={s.prefixBody}>{TEXT.prefixBody}</span>
        </div>
        <div
          className={s.prefixChoices}
          role="radiogroup"
          aria-label={TEXT.prefixLegend}
          aria-busy={savingTarget?.kind === "prefix"}
        >
          {TERMINAL_PREFIX_CHOICES.map((choice) => (
            <button
              key={choice.value}
              type="button"
              role="radio"
              aria-checked={choice.value === prefix}
              className={choice.value === prefix ? [s.prefixChoice, s.prefixOn].join(" ") : s.prefixChoice}
              disabled={settings.data === undefined || save.isPending}
              onClick={() => onPrefix(choice.value)}
            >
              {PREFIX_LABELS[choice.value] ?? choice.value}
            </button>
          ))}
          {savingTarget?.kind === "prefix" && <Spinner size={13} label={TEXT.prefixSaving} />}
        </div>
      </div>

      {saveFailure !== null && failedTarget?.kind === "prefix" && (
        <FailureNotice
          failure={saveFailure}
          title={TEXT.prefixFailed}
          onRetry={() => {
            const last = save.variables;
            if (last !== undefined) save.mutate(last);
          }}
          retryLabel={TEXT.retry}
        />
      )}

      <Field label={TEXT.searchLabel} htmlFor="settings-shortcut-search">
        <TextInput
          id="settings-shortcut-search"
          value={query}
          onChange={setQuery}
          placeholder={TEXT.searchPlaceholder}
        />
      </Field>

      <div className={s.toolbar}>
        <p className={s.count} role="status">
          {TEXT.count(matches.length, resolved.length)}
        </p>
        <span className={s.toolbarSpacer} />
        <Button
          size="sm"
          variant="ghost"
          disabled={customisedCount === 0 || save.isPending || settings.data === undefined}
          title={customisedCount === 0 ? TEXT.resetAllNone : undefined}
          onClick={onResetAll}
        >
          {savingTarget?.kind === "reset-all" ? TEXT.resetAllBusy : TEXT.resetAll}
        </Button>
      </div>

      {saveFailure !== null && failedTarget?.kind === "reset-all" && (
        <FailureNotice failure={saveFailure} title={TEXT.saveFailed} />
      )}

      <div className={s.tableWrap}>
        <table className={s.table}>
          <caption className="visually-hidden">{TEXT.caption}</caption>
          <thead>
            <tr>
              <th scope="col">{TEXT.colAction}</th>
              <th scope="col">{TEXT.colShortcut}</th>
              <th scope="col">{TEXT.colScope}</th>
            </tr>
          </thead>
          <tbody>
            {matches.map((entry) => {
              const action = entry.action;
              const notes = rowNotes(entry);
              const caps = acceleratorCaps(entry.accelerator, action.seriesLen);
              const label = acceleratorLabel(entry.accelerator, action.seriesLen);
              const isCapturing = capturing === action.id;
              const isSaving =
                savingTarget?.kind === "binding" && savingTarget.actionId === action.id;
              const rowRefusal = refused?.actionId === action.id ? refused.message : null;
              const rowFailure =
                saveFailure !== null &&
                failedTarget?.kind === "binding" &&
                failedTarget.actionId === action.id
                  ? saveFailure
                  : null;
              // Only an application binding changes shape inside a session;
              // a universal one is the same chord everywhere.
              const sessionForm =
                action.scope === "application" && action.owner !== "none"
                  ? acceleratorLabel(withPrefix(entry.accelerator, prefix), action.seriesLen)
                  : null;

              return (
                <tr key={action.id} data-unbound={action.owner === "none" ? "true" : undefined}>
                  <th scope="row" className={s.actionCell}>
                    <span className={s.actionName}>{action.title}</span>
                    {notes.map((note) => (
                      <span key={note} className={s.actionNote}>
                        {note}
                      </span>
                    ))}
                    {rowRefusal !== null && (
                      <span className={s.refusal} role="alert">
                        {rowRefusal}
                      </span>
                    )}
                    {rowFailure !== null && (
                      <span className={s.refusal} role="alert">
                        {TEXT.saveFailed} {rowFailure.message}
                      </span>
                    )}
                  </th>

                  <td>
                    <span className={s.shortcutCell}>
                      {action.editable ? (
                        <button
                          type="button"
                          className={isCapturing ? [s.keysButton, s.capturing].join(" ") : s.keysButton}
                          aria-label={TEXT.edit(action.title, label)}
                          title={
                            sessionForm === null ? TEXT.edit(action.title, label) : TEXT.inSession(sessionForm)
                          }
                          disabled={save.isPending || settings.data === undefined}
                          onClick={() => {
                            setRefused(null);
                            setCapturing(isCapturing ? null : action.id);
                          }}
                        >
                          {isCapturing ? (
                            <span className={s.capturingLabel}>{TEXT.capturing}</span>
                          ) : isSaving ? (
                            <Spinner size={13} label={TEXT.saving} />
                          ) : (
                            <span className={s.keys}>
                              {caps.map((cap) => (
                                <kbd key={cap} className={s.key}>
                                  {cap}
                                </kbd>
                              ))}
                            </span>
                          )}
                        </button>
                      ) : (
                        /*
                         * No button at all where a change cannot be stored.
                         * A disabled-looking control that opened a capture and
                         * then refused the save is the pattern this screen
                         * exists to stop.
                         */
                        <span
                          className={s.keysFixed}
                          title={action.unrebindableReason ?? TEXT.fixed(action.title)}
                        >
                          <span className={s.keys}>
                            {caps.map((cap) => (
                              <kbd key={cap} className={s.key} data-muted={action.owner === "none"}>
                                {cap}
                              </kbd>
                            ))}
                          </span>
                        </span>
                      )}

                      {entry.customised && action.editable && (
                        <button
                          type="button"
                          className={s.resetButton}
                          title={TEXT.reset(action.title)}
                          aria-label={TEXT.reset(action.title)}
                          disabled={save.isPending}
                          onClick={() => onResetOne(action.id)}
                        >
                          <Icon name="arrow-left" size={12} />
                        </button>
                      )}
                    </span>
                    {isCapturing && (
                      <span className={s.captureHint} role="status">
                        {TEXT.capturingHint}
                      </span>
                    )}
                  </td>

                  <td className={s.scopeCell}>{scopeLabel(entry)}</td>
                </tr>
              );
            })}
            {matches.length === 0 && (
              <tr>
                <td className={s.empty} colSpan={3}>
                  {TEXT.empty}
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </SettingsSection>
  );
}
