/**
 * Application settings.
 *
 * Five panels behind a vertical tab list, filling whatever space the shell
 * hands it. The screen owns the read of `settings_get` and every write through
 * `settings_set`; the sections are given the values and a `save` callback, so
 * there is one place where a failed write is caught and one place where the
 * applied theme is put back afterwards.
 *
 * Both states of the round trip are visible. Until the read lands the panel
 * says what it is waiting for; if it fails, the core's own message is shown
 * with a way to try again, because a settings screen that silently shows
 * defaults is a settings screen that quietly loses your settings.
 *
 * Leaving returns to whichever screen opened this one — the title bar and the
 * palette reach it from the main window, the vault picker reaches it before any
 * vault is open. `goBack()` in stores/app.ts is what knows which; sending
 * everyone to the main window stranded a user who arrived from the picker in a
 * window with no vault behind it.
 */

import { useEffect, useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import type { KeyboardEvent } from "react";

import { Button } from "@/components/Button";
import { FailureNotice } from "@/components/FailureNotice";
import { Icon } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { applyTerminalAppearance } from "@/features/sessions/terminals";
import { asFailure, ipc } from "@/lib/ipc";
import type { AppSettings as AppSettingsDto, TerminalAppearance } from "@/lib/ipc";
import { qk } from "@/lib/queryKeys";
import { useApp } from "@/stores/app";

import { AboutSection } from "./AboutSection";
import { AppearanceSection } from "./AppearanceSection";
import { LanguageSection } from "./LanguageSection";
import { ShortcutsSection } from "./ShortcutsSection";
import { TerminalSection } from "./TerminalSection";
import { UpdatesSection } from "./UpdatesSection";
import type { SaveFailure, SectionProps, SettingsField } from "./types";
import s from "./AppSettings.module.css";

const TEXT = {
  title: "Settings",
  close: "Close settings",
  closeHint: "Close settings (Esc)",

  navAppearance: "Appearance",
  navTerminal: "Terminal",
  navLanguage: "Language",
  navShortcuts: "Shortcuts",
  navUpdates: "Updates",
  navAbout: "About",

  sections: "Settings sections",

  loading: "Reading your settings…",
  loadFailed: "Your settings could not be read.",
  loadRetry: "Try again",
  loadFailedClose: "Close settings",
} as const;

const TABS = [
  { id: "appearance", label: TEXT.navAppearance },
  { id: "terminal", label: TEXT.navTerminal },
  { id: "language", label: TEXT.navLanguage },
  { id: "shortcuts", label: TEXT.navShortcuts },
  { id: "updates", label: TEXT.navUpdates },
  { id: "about", label: TEXT.navAbout },
] as const;

type TabId = (typeof TABS)[number]["id"];

/**
 * Every setting this screen writes.
 *
 * `SettingsField` in `types.ts` is what the sections sharing `SectionProps`
 * write. The terminal section does not share them — its control is a whole
 * appearance object rather than a single value, so it takes its own props —
 * but its write goes through the same mutation, so the mutation's field is the
 * wider union and the shared props are narrowed back down below.
 */
type SaveField = SettingsField | "terminal";

interface SaveVariables {
  field: SaveField;
  patch: Partial<AppSettingsDto>;
}

interface WideFailure {
  field: SaveField;
  failure: SaveFailure["failure"];
}

export function AppSettings() {
  const goBack = useApp((state) => state.goBack);
  const setTheme = useApp((state) => state.setTheme);
  const setLocale = useApp((state) => state.setLocale);

  const queryClient = useQueryClient();
  const [tab, setTab] = useState<TabId>("appearance");
  const [failure, setFailure] = useState<WideFailure | null>(null);
  const tabRefs = useRef<(HTMLButtonElement | null)[]>([]);

  // The builder, so a write here lands in the same cache entry anything else
  // reading settings would look in.
  const settings = useQuery({
    queryKey: qk.settings(),
    queryFn: ipc.getSettings,
  });

  const save = useMutation<AppSettingsDto, unknown, SaveVariables>({
    mutationFn: (variables) => ipc.setSettings(variables.patch),
    onSuccess: (next) => {
      setFailure(null);
      queryClient.setQueryData(qk.settings(), next);
    },
    onError: (error, variables) => {
      setFailure({ field: variables.field, failure: asFailure(error) });

      // The choice was applied before it was stored. It did not store, so the
      // window goes back to what the core still holds rather than showing a
      // theme nobody saved.
      const stored = queryClient.getQueryData<AppSettingsDto>(qk.settings());
      if (stored !== undefined) {
        setTheme(stored.theme);
        setLocale(stored.locale);
        // The terminal appearance is applied to live sessions before it is
        // stored, exactly as the theme is, so a failed write has to put the
        // open terminals back too.
        applyTerminalAppearance(stored.terminal);
      }
    },
  });

  const loaded = settings.data;
  const needsSettings = tab === "appearance" || tab === "terminal" || tab === "language";

  // What the core holds is what the window shows: reconciling here means a
  // settings file edited between runs takes effect the moment it is read.
  useEffect(() => {
    if (loaded === undefined) return;
    setTheme(loaded.theme);
    setLocale(loaded.locale);
    // Terminals are created outside React and read this at start-up on their
    // own; pushing it again here is what makes a settings file edited between
    // runs, or a save from this screen, reach sessions already open.
    applyTerminalAppearance(loaded.terminal);
  }, [loaded, setTheme, setLocale]);

  // Escape leaves, as it does from every other panel in the application — back
  // to whatever opened settings, which is not always the main window.
  useEffect(() => {
    function onKey(event: globalThis.KeyboardEvent) {
      if (event.key === "Escape") goBack();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [goBack]);

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

  const activeField: SaveField | null =
    save.isPending && save.variables !== undefined ? save.variables.field : null;

  const retrySave = () => {
    const last = save.variables;
    if (last !== undefined) save.mutate(last);
  };

  // Narrowed back to what the shared sections understand. A section renders a
  // failure only when the field is one of its own, so handing it a field it
  // has no control for would show an error beside nothing.
  const sectionProps: Omit<SectionProps, "settings"> = {
    onSave: (field, patch) => save.mutate({ field, patch }),
    savingField: activeField === "terminal" ? null : activeField,
    failure:
      failure !== null && failure.field !== "terminal"
        ? { field: failure.field, failure: failure.failure }
        : null,
    onRetrySave: retrySave,
  };

  function saveTerminal(terminal: TerminalAppearance) {
    save.mutate({ field: "terminal", patch: { terminal } });
  }

  return (
    <div className={s.screen}>
      <header className={s.header}>
        <span className={s.headerIcon} aria-hidden="true">
          <Icon name="settings" size={15} />
        </span>
        <h1 className={s.headerTitle}>{TEXT.title}</h1>
        <span className={s.headerSpacer} />
        <button
          type="button"
          className={s.closeButton}
          onClick={goBack}
          title={TEXT.closeHint}
          aria-label={TEXT.close}
        >
          <Icon name="x" size={15} />
        </button>
      </header>

      <div className={s.body}>
        <div
          className={s.nav}
          role="tablist"
          aria-orientation="vertical"
          aria-label={TEXT.sections}
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
              id={`settings-tab-${entry.id}`}
              aria-controls={`settings-panel-${entry.id}`}
              aria-selected={entry.id === tab}
              tabIndex={entry.id === tab ? 0 : -1}
              onClick={() => setTab(entry.id)}
            >
              {entry.label}
            </button>
          ))}
        </div>

        <div
          className={s.panel}
          role="tabpanel"
          id={`settings-panel-${tab}`}
          aria-labelledby={`settings-tab-${tab}`}
          tabIndex={0}
        >
          {needsSettings && settings.isPending && (
            <p className={s.loading}>
              <Spinner size={16} label={TEXT.loading} />
              {TEXT.loading}
            </p>
          )}

          {needsSettings && settings.isError && (
            <div className={s.loadFailure}>
              <FailureNotice
                failure={asFailure(settings.error)}
                title={TEXT.loadFailed}
                onRetry={() => void settings.refetch()}
                retryLabel={TEXT.loadRetry}
              >
                <Button size="sm" variant="ghost" onClick={goBack}>
                  {TEXT.loadFailedClose}
                </Button>
              </FailureNotice>
            </div>
          )}

          {loaded !== undefined && tab === "appearance" && (
            <AppearanceSection settings={loaded} {...sectionProps} />
          )}
          {loaded !== undefined && tab === "terminal" && (
            <TerminalSection
              settings={loaded}
              onSave={saveTerminal}
              saving={activeField === "terminal"}
              failure={failure !== null && failure.field === "terminal" ? failure.failure : null}
              onRetrySave={retrySave}
            />
          )}
          {loaded !== undefined && tab === "language" && (
            <LanguageSection settings={loaded} {...sectionProps} />
          )}

          {/* These three read nothing from the vault, so a failed read of the
              settings file does not take them down with it. */}
          {tab === "shortcuts" && <ShortcutsSection />}
          {tab === "updates" && <UpdatesSection />}
          {tab === "about" && <AboutSection />}
        </div>
      </div>
    </div>
  );
}
