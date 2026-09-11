/**
 * The terminal's colours and font.
 *
 * Three things decided the shape of this screen.
 *
 * **The preview shows real output.** Sixteen abstract swatches tell you what
 * the colours are; they do not tell you whether you can read a diff at two in
 * the morning. So the preview is a prompt, a coloured directory listing, a
 * diff and an error line — the four things anyone actually looks at — set in
 * the font that is about to be applied, so a font name that resolved to
 * nothing is visible rather than mysterious.
 *
 * **Contrast is computed and reported, never enforced.** The design system
 * requires WCAG 2.2 AA, and a terminal is the one surface where the user picks
 * the colours. Red on a dark blue background is the classic way a theme becomes
 * unusable, and it becomes unusable at exactly the moment you need to read a
 * stack trace. So every colour is rated against the chosen background and the
 * ones that fall short are named with their ratio. Nothing is blocked: it is
 * the user's terminal, and an accessibility check that overrules a deliberate
 * choice is a bug with a certificate.
 *
 * **A change reaches open sessions immediately.** `terminals.ts` holds the live
 * `Terminal` instances, so the new palette is pushed into them as it is edited
 * rather than waiting for a save, let alone a reconnect. The write follows,
 * debounced, because dragging a colour picker must not be one settings write
 * per frame. If the write fails, the screen above puts the stored appearance
 * back — the same contract the theme has, and the editor below follows it too:
 * what the fields show is reconciled with what the core actually stored, so a
 * refused value is not left sitting in the editor waiting to be sent again.
 */

import type { TFunction } from "i18next";
import { useEffect, useRef, useState } from "react";

import { Button } from "@/components/Button";
import { Callout } from "@/components/Callout";
import { FailureNotice } from "@/components/FailureNotice";
import { Field } from "@/components/Field";
import { Icon } from "@/components/Icon";
import { Spinner } from "@/components/Spinner";
import { TextInput } from "@/components/TextInput";
import { applyTerminalAppearance } from "@/features/sessions";
import { useSystemTheme } from "@/hooks/useSystemTheme";
import { formatNumber, useLocale, useT } from "@/i18n";
import type { AppSettings as AppSettingsDto, IpcFailure, TerminalAppearance } from "@/lib/ipc";
import {
  MAX_TERMINAL_FONT_SIZE,
  MIN_TERMINAL_FONT_SIZE,
  TERMINAL_ANSI_KEYS,
  TERMINAL_COLOR_KEYS,
  TERMINAL_PALETTES,
  baseTerminalColors,
  contrastRatio,
  gradeContrast,
  isTerminalPaletteId,
  normaliseHex,
  opaqueHex,
  paletteById,
  paletteCreditKey,
  paletteNameKey,
  parseHexColor,
  pruneOverrides,
  resolvePaletteId,
  resolveTerminalColors,
  type ContrastGrade,
  type InterfaceTheme,
  type TerminalColorKey,
  type TerminalColors,
} from "@/lib/terminalPalette";
import { useApp } from "@/stores/app";

import { SettingsSection } from "./SettingsSection";
import s from "./TerminalSection.module.css";

/**
 * How long a change waits before it is written.
 *
 * A colour picker fires on every pointer move. The terminal is repainted on
 * every one of those — that is free and it is the point — but the settings
 * file is not written until the hand stops.
 */
const SAVE_DEBOUNCE_MS = 300;

/**
 * Whether two appearances are the same value.
 *
 * Compared by content rather than by identity: the settings live in one query
 * cache entry, so writing any other setting hands this section a fresh object
 * holding an unchanged terminal appearance. Treating that as a change would
 * throw away whatever is being typed for a reason the user cannot see.
 */
function sameAppearance(a: TerminalAppearance, b: TerminalAppearance): boolean {
  if (a === b) return true;
  if (a.palette !== b.palette) return false;
  if (a.fontFamily !== b.fontFamily) return false;
  if (a.fontSize !== b.fontSize) return false;

  const keys = Object.keys(a.overrides);
  if (keys.length !== Object.keys(b.overrides).length) return false;
  return keys.every((key) => a.overrides[key] === b.overrides[key]);
}


/**
 * The catalogue key naming each editable colour.
 *
 * Keys, not labels: the map is module-level, and a label resolved at import
 * would keep the language the application started in for the rest of the
 * session.
 */
const COLOUR_LABEL_KEYS: Record<TerminalColorKey, `terminal.colours.${TerminalColorKey}`> = {
  background: "terminal.colours.background",
  foreground: "terminal.colours.foreground",
  cursor: "terminal.colours.cursor",
  cursorAccent: "terminal.colours.cursorAccent",
  selection: "terminal.colours.selection",
  black: "terminal.colours.black",
  red: "terminal.colours.red",
  green: "terminal.colours.green",
  yellow: "terminal.colours.yellow",
  blue: "terminal.colours.blue",
  magenta: "terminal.colours.magenta",
  cyan: "terminal.colours.cyan",
  white: "terminal.colours.white",
  brightBlack: "terminal.colours.brightBlack",
  brightRed: "terminal.colours.brightRed",
  brightGreen: "terminal.colours.brightGreen",
  brightYellow: "terminal.colours.brightYellow",
  brightBlue: "terminal.colours.brightBlue",
  brightMagenta: "terminal.colours.brightMagenta",
  brightCyan: "terminal.colours.brightCyan",
  brightWhite: "terminal.colours.brightWhite",
};

/** The keys that name a colour a program prints text in. */
const TEXT_KEYS: readonly TerminalColorKey[] = ["foreground", ...TERMINAL_ANSI_KEYS];

interface TerminalSectionProps {
  settings: AppSettingsDto;
  /** Called with the whole appearance: palette and overrides are one decision. */
  onSave: (terminal: TerminalAppearance) => void;
  saving: boolean;
  /** The last write of this setting that failed, or null. */
  failure: IpcFailure | null;
  onRetrySave: () => void;
}

// ----------------------------------------------------------------- preview --

interface PreviewProps {
  colors: TerminalColors;
  fontFamily: string;
  fontSize: number;
  /** The compact form used on a palette card. */
  compact?: boolean | undefined;
}

/**
 * A terminal, painted.
 *
 * The lines are the ones that decide whether a palette is usable: a prompt, a
 * `ls --color` listing where four file kinds are four colours, a diff whose
 * two signs must not read as the same colour, and an error. It is
 * `aria-hidden` because it is a picture of colours — the substance for anyone
 * not looking at it is the contrast report below, which is text.
 */
/*
 * The strings below are a mock-up of what a remote shell prints: a prompt, an
 * `ls --color` listing, a diff, a systemd failure. Terminal output belongs to
 * the host and is never translated — docs/features/i18n.md, "What is never
 * translated" — so a translated preview would be a picture of something that
 * cannot happen. It is `aria-hidden` for the same reason: the substance for a
 * screen-reader user is the contrast report below, which is real text.
 */
/* eslint-disable remoter-i18n/no-literal-jsx-text -- simulated remote output, see above */
function TerminalPreview({ colors, fontFamily, fontSize, compact = false }: PreviewProps) {
  const frame = {
    background: colors.background,
    color: colors.foreground,
    fontFamily,
    fontSize: `${fontSize}px`,
  };

  const prompt = (
    <>
      <span style={{ color: colors.brightGreen }}>deploy@mail-01</span>
      <span style={{ color: colors.brightBlack }}>:</span>
      <span style={{ color: colors.brightBlue }}>~/postfix</span>
      <span style={{ color: colors.foreground }}>$ </span>
    </>
  );

  if (compact) {
    return (
      <pre className={[s.preview, s.previewCompact].join(" ")} style={frame} aria-hidden="true">
        <div>
          {prompt}
          <span>ls</span>
        </div>
        <div>
          <span style={{ color: colors.blue }}>conf.d</span>{"  "}
          <span style={{ color: colors.green }}>reload.sh</span>{"  "}
          <span style={{ color: colors.red }}>main.cf.bak</span>
        </div>
        <div>
          <span style={{ color: colors.brightRed }}>error</span>
          <span>: relay access denied</span>
        </div>
      </pre>
    );
  }

  return (
    <pre className={s.preview} style={frame} aria-hidden="true">
      <div>
        {prompt}
        <span>ls --color</span>
      </div>
      <div>
        <span style={{ color: colors.blue }}>conf.d</span>{"      "}
        <span style={{ color: colors.green }}>reload.sh</span>{"   "}
        <span style={{ color: colors.red }}>main.cf.bak</span>{"   "}
        <span style={{ color: colors.magenta }}>queue.tar.gz</span>{"   "}
        <span>main.cf</span>
      </div>
      <div>
        {prompt}
        <span>git diff main.cf</span>
      </div>
      <div>
        <span style={{ color: colors.brightBlack }}>@@ -18,7 +18,7 @@</span>
      </div>
      <div>
        <span style={{ color: colors.red }}>-smtpd_tls_security_level = may</span>
      </div>
      <div>
        <span style={{ color: colors.green }}>+smtpd_tls_security_level = encrypt</span>
      </div>
      <div>
        {prompt}
        <span>systemctl reload postfix</span>
      </div>
      <div>
        <span style={{ color: colors.yellow }}>warning</span>
        <span>: postfix.service changed on disk</span>
      </div>
      <div>
        <span style={{ color: colors.brightRed }}>error</span>
        <span>: Job for postfix.service failed. See </span>
        <span style={{ background: colors.selection }}>journalctl -xeu postfix</span>
      </div>
      <div>
        {prompt}
        <span style={{ background: colors.cursor, color: colors.cursorAccent }}>&nbsp;</span>
      </div>
    </pre>
  );
}

/* eslint-enable remoter-i18n/no-literal-jsx-text */

/**
 * A contrast ratio, as `4.5:1`.
 *
 * The number goes through `Intl` — a German reader writes it `4,5` — and the
 * `:1` comes from the catalogue, because it is notation a locale could
 * conceivably write differently and is not ours to hardcode at the call site.
 */
function contrastRatioText(locale: string, t: TFunction<"settings">, ratio: number): string {
  return t("terminal.contrastRatio", { ratio: formatNumber(locale, ratio, 1) });
}

// ---------------------------------------------------------------- section ---

export function TerminalSection({
  settings,
  onSave,
  saving,
  failure,
  onRetrySave,
}: TerminalSectionProps) {
  const t = useT("settings");
  const tCommon = useT("common");
  const { code: locale } = useLocale();
  const theme = useApp((state) => state.theme);
  const systemTheme = useSystemTheme();
  const interfaceTheme: InterfaceTheme = theme === "system" ? systemTheme : theme;

  const [draft, setDraft] = useState<TerminalAppearance>(settings.terminal);
  /**
   * What is in a hex field while it is being typed in.
   *
   * A half-typed `#1a1` is not a colour, and the draft must not take it — but
   * the field has to show it, or the user cannot get to the fourth character.
   */
  const [typing, setTyping] = useState<Partial<Record<TerminalColorKey, string>>>({});

  const pending = useRef<TerminalAppearance | null>(null);
  const timer = useRef<number | null>(null);
  const onSaveRef = useRef(onSave);

  useEffect(() => {
    onSaveRef.current = onSave;
  }, [onSave]);

  /**
   * What the core holds, and what this editor is showing.
   *
   * The draft was seeded from the stored appearance once and then never looked
   * at it again, which made the editor and the core disagree in two ways. A
   * write the core refused left the rejected value in the fields, so the next
   * edit — a font size, an unrelated colour — sent it back with it, applying a
   * value the user was told had not been stored and had not asked for again. A
   * write the core stored in a normalised form left the editor showing the
   * unnormalised one until the screen was reopened.
   *
   * So: when the stored appearance changes, or when a write is refused, the
   * draft goes back to whatever the core actually holds. Both are compared
   * against what this effect last saw, because a refusal leaves the stored
   * value untouched — there is nothing in it to notice.
   */
  const stored = settings.terminal;
  const seenStored = useRef(stored);
  const seenFailure = useRef(failure);

  useEffect(() => {
    const storedChanged = !sameAppearance(seenStored.current, stored);
    const refused = failure !== null && failure !== seenFailure.current;
    seenStored.current = stored;
    seenFailure.current = failure;

    if (!storedChanged && !refused) return;
    // An edit still inside its debounce has not been offered to the core yet.
    // It is the newer intent, and replacing it with the stored value would
    // undo something the user did a fraction of a second ago.
    if (pending.current !== null) return;
    if (sameAppearance(draft, stored)) return;

    setDraft(stored);
    // Half-typed hex text belongs to the draft it was being typed into. Kept,
    // it would show over a value the user never entered.
    setTyping({});
    // Open sessions are put back by the screen above — it owns the write, so
    // it is the one that knows a failed one has to be undone everywhere.
  }, [stored, failure, draft]);

  // A tab switch away from this panel unmounts it. Whatever was still waiting
  // out its debounce is written now rather than dropped: an edit the user made
  // and watched take effect must not be lost because they moved on quickly.
  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
      const outstanding = pending.current;
      pending.current = null;
      if (outstanding !== null) onSaveRef.current(outstanding);
    },
    [],
  );

  function commit(next: TerminalAppearance) {
    setDraft(next);
    // Applied before it is stored, as the theme is. The screen above puts the
    // stored value back if the write fails.
    applyTerminalAppearance(next);

    pending.current = next;
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => {
      timer.current = null;
      const outstanding = pending.current;
      pending.current = null;
      if (outstanding !== null) onSaveRef.current(outstanding);
    }, SAVE_DEBOUNCE_MS);
  }

  const colors = resolveTerminalColors(draft, interfaceTheme);
  const base = baseTerminalColors(draft, interfaceTheme);
  const overrides = draft.overrides;
  const overriddenCount = Object.keys(pruneOverrides(draft, interfaceTheme)).length;

  // What "follow the interface theme" currently means, named on screen so the
  // option is a statement rather than a promise.
  const resolvedPalette = paletteById(
    resolvePaletteId(isTerminalPaletteId(draft.palette) ? draft.palette : "auto", interfaceTheme),
  );

  const fontFamily = draft.fontFamily.trim();
  const previewFont = fontFamily === "" ? "var(--font-mono)" : `${fontFamily}, var(--font-mono)`;

  function choosePalette(id: string) {
    if (id === draft.palette) return;
    // Overrides are kept. They are stored per colour precisely so that
    // switching palette moves everything that was left alone and nothing that
    // was not; "Reset every colour" is one button away when that is not wanted.
    commit({ ...draft, palette: id });
  }

  /**
   * The platform colour control, which has no alpha channel.
   *
   * `selection` is translucent in every palette here, and a picker that
   * silently made it opaque would turn a highlight into a block that hides the
   * text under it. So whatever transparency the colour already had is carried
   * across, and the hex field stays the way to change it.
   */
  function setFromPicker(key: TerminalColorKey, value: string) {
    const existing = parseHexColor(colors[key]);
    const picked = normaliseHex(value);
    if (picked === null) return;
    if (existing === null || existing.a >= 1) {
      setColor(key, picked);
      return;
    }
    const alpha = Math.round(existing.a * 255)
      .toString(16)
      .padStart(2, "0");
    setColor(key, `${picked}${alpha}`);
  }

  function setColor(key: TerminalColorKey, value: string) {
    const hex = normaliseHex(value);
    if (hex === null) return;
    const next = { ...overrides, [key]: hex };
    commit({ ...draft, overrides: pruneOverrides({ ...draft, overrides: next }, interfaceTheme) });
  }

  function resetColor(key: TerminalColorKey) {
    const next = { ...overrides };
    delete next[key];
    setTyping((fields) => {
      const cleared = { ...fields };
      delete cleared[key];
      return cleared;
    });
    commit({ ...draft, overrides: next });
  }

  function resetAll() {
    setTyping({});
    commit({ ...draft, overrides: {} });
  }

  const failures = TEXT_KEYS.map((key) => {
    const ratio = contrastRatio(colors[key], colors.background);
    return { key, ratio, grade: gradeContrast(ratio) };
  }).filter((entry) => entry.grade === "large" || entry.grade === "fail");

  const onlyBlacks = failures.every(
    (entry) => entry.key === "black" || entry.key === "brightBlack",
  );

  return (
    <>
      <SettingsSection title={t("terminal.paletteTitle")} description={t("terminal.paletteDescription")}>
        <div className={s.group} role="radiogroup" aria-label={t("terminal.paletteTitle")}>
          <label className={s.autoRow}>
            <input
              className={s.radio}
              type="radio"
              name="remoter-terminal-palette"
              value="auto"
              checked={draft.palette === "auto"}
              onChange={() => choosePalette("auto")}
              aria-label={t("terminal.auto")}
            />
            <span className={s.mark} aria-hidden="true" />
            <span className={s.autoBody}>
              <span className={s.autoName}>{t("terminal.auto")}</span>
              <span className={s.autoHint}>
                {t("terminal.autoCredit")}.{" "}
                {resolvedPalette !== undefined && draft.palette === "auto"
                  ? t("terminal.autoResolved", { name: t(paletteNameKey(resolvedPalette.id)) })
                  : ""}
              </span>
            </span>
          </label>

          <div className={s.paletteGrid}>
            {TERMINAL_PALETTES.map((palette) => (
              <label key={palette.id} className={s.paletteCard}>
                <input
                  className={s.radio}
                  type="radio"
                  name="remoter-terminal-palette"
                  value={palette.id}
                  checked={draft.palette === palette.id}
                  onChange={() => choosePalette(palette.id)}
                  // Name and credit are joined through a message rather than
                  // with a template literal: the separator between a title and
                  // its attribution is not an em dash in every language, and
                  // concatenating copy is the one thing the catalogue rules
                  // forbid outright (docs/features/i18n.md).
                  aria-label={t("terminal.paletteLabel", {
                    name: t(paletteNameKey(palette.id)),
                    credit: t(paletteCreditKey(palette.id)),
                  })}
                />
                <TerminalPreview
                  colors={palette.colors}
                  fontFamily={previewFont}
                  fontSize={11}
                  compact
                />
                <span className={s.paletteLabel}>
                  <span className={s.mark} aria-hidden="true" />
                  <span className={s.paletteText}>
                    <span className={s.paletteName}>{t(paletteNameKey(palette.id))}</span>
                    <span className={s.paletteCredit}>{t(paletteCreditKey(palette.id))}</span>
                  </span>
                </span>
              </label>
            ))}
          </div>
        </div>


        <div className={s.previewBlock}>
          <p className={s.previewHead}>
            <span className={s.previewTitle}>{t("terminal.previewLabel")}</span>
            <span className={s.previewNote}>{t("terminal.previewNote")}</span>
          </p>
          <TerminalPreview
            colors={colors}
            fontFamily={previewFont}
            fontSize={draft.fontSize}
          />
        </div>

        {saving && (
          <p className={s.saving}>
            <Spinner size={14} label={t("terminal.saving")} />
            {t("terminal.saving")}
          </p>
        )}

        {failure !== null && (
          <FailureNotice
            failure={failure}
            title={t("terminal.saveFailed")}
            onRetry={onRetrySave}
            retryLabel={tCommon("action.saveAgain")}
          />
        )}

        <p className={s.note}>{t("terminal.scope")}</p>
      </SettingsSection>

      <SettingsSection title={t("terminal.contrastTitle")} description={t("terminal.contrastDescription")}>
        {failures.length === 0 ? (
          <p className={s.contrastClear}>
            <span className={s.contrastClearIcon} aria-hidden="true">
              <Icon name="check" size={14} />
            </span>
            {t("terminal.contrastClear")}
          </p>
        ) : (
          <>
            <Callout
              tone={onlyBlacks ? "neutral" : "warning"}
              title={t("terminal.contrastCount", { count: failures.length })}
            >
              {onlyBlacks ? t("terminal.contrastBlacks") : t("terminal.contrastWarning")}
            </Callout>
            <ul className={s.contrastList}>
              {failures.map((entry) => (
                <li key={entry.key} className={s.contrastRow}>
                  <span
                    className={s.contrastSwatch}
                    style={{ background: colors.background, color: colors[entry.key] }}
                    aria-hidden="true"
                  >
                    {t("terminal.contrastSample")}
                  </span>
                  <span className={s.contrastName}>{t(COLOUR_LABEL_KEYS[entry.key])}</span>
                  <span className={s.contrastValue}>{contrastRatioText(locale, t, entry.ratio)}</span>
                  <span className={[s.contrastTag, s[entry.grade]].join(" ")}>
                    <Icon name="alert" size={12} />
                    {entry.grade === "fail" ? t("terminal.contrastUnreadable") : t("terminal.contrastHard")}
                  </span>
                </li>
              ))}
            </ul>
          </>
        )}
      </SettingsSection>

      <SettingsSection title={t("terminal.coloursTitle")} description={t("terminal.coloursDescription")}>
        <div className={s.resetRow}>
          <Button size="sm" variant="secondary" onClick={resetAll} disabled={overriddenCount === 0}>
            {t("terminal.resetAll")}
          </Button>
          <span className={s.resetHint}>
            {overriddenCount === 0 ? t("terminal.resetAllNone") : t("terminal.overriddenCount", { count: overriddenCount })}
          </span>
        </div>

        <div className={s.colorGrid}>
          {TERMINAL_COLOR_KEYS.map((key) => {
            const label = t(COLOUR_LABEL_KEYS[key]);
            const current = colors[key];
            const typed = typing[key];
            const shown = typed ?? current;
            const invalid = typed !== undefined && normaliseHex(typed) === null;
            const changed = current !== base[key];
            const ratio = contrastRatio(current, colors.background);
            const grade: ContrastGrade | null = TEXT_KEYS.includes(key)
              ? gradeContrast(ratio)
              : null;

            return (
              <div key={key} className={s.colorRow}>
                <span className={s.colorName}>
                  {label}
                  {changed && <span className={s.changedTag}>{t("terminal.overridden")}</span>}
                </span>

                <span className={s.colorControls}>
                  <input
                    className={s.picker}
                    type="color"
                    value={opaqueHex(current)}
                    onChange={(event) => setFromPicker(key, event.target.value)}
                    aria-label={t("terminal.pickLabel", { name: label })}
                  />
                  <span className={s.hexField}>
                    <TextInput
                      value={shown}
                      mono
                      invalid={invalid}
                      ariaLabel={t("terminal.hexLabel", { name: label })}
                      onChange={(value) => {
                        setTyping((fields) => ({ ...fields, [key]: value }));
                        setColor(key, value);
                      }}
                    />
                  </span>
                  {grade !== null && (
                    <span
                      className={[s.gradeChip, s[grade]].join(" ")}
                      title={t("terminal.contrastAgainstBackground", { ratio: contrastRatioText(locale, t, ratio) })}
                    >
                      {contrastRatioText(locale, t, ratio)}
                    </span>
                  )}
                  <button
                    type="button"
                    className={s.resetOne}
                    onClick={() => resetColor(key)}
                    disabled={!changed}
                    aria-label={t("terminal.resetOne", { name: label })}
                    title={t("terminal.resetOne", { name: label })}
                  >
                    <Icon name="arrow-left" size={13} />
                  </button>
                </span>

                {invalid && (
                  <span className={s.colorError} role="alert">
                    {t("terminal.invalidHex")}
                  </span>
                )}
              </div>
            );
          })}
        </div>
      </SettingsSection>

      <SettingsSection title={t("terminal.fontTitle")} description={t("terminal.fontDescription")}>
        <div className={s.fontRow}>
          <div className={s.fontFamily}>
            <Field
              label={t("terminal.fontFamilyLabel")}
              help={`${t("terminal.fontFamilyDefault")} ${t("terminal.fontFamilyHelp")}`}
            >
              <TextInput
                value={draft.fontFamily}
                mono
                placeholder={t("terminal.fontFamilyPlaceholder")}
                ariaLabel={t("terminal.fontFamilyLabel")}
                onChange={(value) => commit({ ...draft, fontFamily: value })}
              />
            </Field>
          </div>

          <div className={s.fontSize}>
            <Field label={t("terminal.fontSizeLabel")} help={t("terminal.fontSizeHelp", {
                min: MIN_TERMINAL_FONT_SIZE,
                max: MAX_TERMINAL_FONT_SIZE,
              })}>
              <input
                className={s.sizeInput}
                type="number"
                inputMode="numeric"
                min={MIN_TERMINAL_FONT_SIZE}
                max={MAX_TERMINAL_FONT_SIZE}
                step={1}
                value={draft.fontSize}
                aria-label={t("terminal.fontSizeLabel")}
                onChange={(event) => {
                  const size = Number.parseInt(event.target.value, 10);
                  if (Number.isNaN(size)) return;
                  const clamped = Math.min(
                    Math.max(size, MIN_TERMINAL_FONT_SIZE),
                    MAX_TERMINAL_FONT_SIZE,
                  );
                  commit({ ...draft, fontSize: clamped });
                }}
              />
            </Field>
          </div>
        </div>
      </SettingsSection>
    </>
  );
}
