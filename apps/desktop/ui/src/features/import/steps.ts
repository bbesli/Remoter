/**
 * The wizard's step model and its gating.
 *
 * Kept out of the component because "why is Continue disabled?" is a question
 * the interface has to answer in words, and a rule you can only reach by
 * rendering eight steps of React is a rule nobody tests. Every gate here
 * returns the sentence shown on the blocked control rather than a boolean, so
 * a disabled button always has something to say for itself.
 *
 * Steps 3 and 7 are work, not input: the wizard moves through them by itself
 * and they exist in the rail so that the wait has a place on the screen.
 */

import type { ImportSource, IpcFailure } from "@/lib/ipc";

export type StepNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

/**
 * The two refusals that mean "the document password is the thing to change".
 *
 * Detection reads the `<Connections>` header and usually knows, but it cannot
 * always: a file whose format the sniffer could not place has no header read at
 * all, and the format the user picked by hand carries none either. In those
 * cases the parse is the first thing that finds out, and its refusal is the
 * only signal the interface gets. Codes rather than sentences — the wording
 * comes from `locales/<lang>/errors.json` and a match on it would break the
 * moment anyone translated it.
 */
export function wantsDocumentPassword(failure: IpcFailure | null): boolean {
  if (failure === null) return false;
  return (
    failure.code === "import.password-required" ||
    failure.code === "import.wrong-password" ||
    failure.code === "import.archive-password-required" ||
    failure.code === "import.archive-wrong-password"
  );
}

/**
 * A rail label's key in the `import` catalogue.
 *
 * Spelled out rather than left as a template type: `t()` is typed against the
 * catalogue's own keys, and only an exact literal proves the key is one of
 * them. A renamed entry in `locales/en/import.json` is then a compile error
 * here rather than a humanised key on screen.
 */
export type StepLabelKey =
  | "rail.step.source"
  | "rail.step.secrets"
  | "rail.step.parse"
  | "rail.step.preview"
  | "rail.step.report"
  | "rail.step.destination"
  | "rail.step.commit"
  | "rail.step.result";

export interface StepDefinition {
  n: StepNumber;
  /**
   * A key rather than a sentence, because this module is pure and `useT` is a
   * hook: the wizard translates it where it draws it. Every gate below does
   * the same, which is also what lets `steps.test.ts` assert on the rule
   * rather than on a particular language's wording.
   */
  labelKey: StepLabelKey;
}

/**
 * The design's rail has "Conflicts" at 5. There is no conflict resolution in
 * the core — nothing compares an import against what is already in the vault —
 * so drawing that step would be a promise the wizard cannot keep. The report,
 * which the core does produce, takes the slot; the preview says plainly what
 * to do instead.
 */
export const STEPS: readonly StepDefinition[] = [
  { n: 1, labelKey: "rail.step.source" },
  { n: 2, labelKey: "rail.step.secrets" },
  { n: 3, labelKey: "rail.step.parse" },
  { n: 4, labelKey: "rail.step.preview" },
  { n: 5, labelKey: "rail.step.report" },
  { n: 6, labelKey: "rail.step.destination" },
  { n: 7, labelKey: "rail.step.commit" },
  { n: 8, labelKey: "rail.step.result" },
];

/** Everything the gates need to know, and nothing that would make them async. */
export interface WizardFacts {
  hasFile: boolean;
  /** What the file will be parsed as: detected, or chosen by the user. */
  format: ImportSource | null;
  /** Whether the detection on screen is the detection of the current path. */
  detected: boolean;
  /**
   * Whether a document password has to be supplied — because the file's header
   * says so, or because the parse came back asking for one. See
   * {@link wantsDocumentPassword}.
   */
  passwordRequired: boolean;
  hasPassword: boolean;
  hasPreview: boolean;
  /** Nodes still ticked in the preview. Zero means there is nothing to write. */
  includedCount: number;
  committed: boolean;
  /** A detect, parse or commit is in flight. */
  busy: boolean;
}

/**
 * The refusals, as catalogue keys.
 *
 * The sentences themselves live in `locales/en/import.json` under `gate.*`;
 * what a gate returns is the key, which the wizard passes to `t()`. Keeping
 * the words out of here is what lets these rules be tested — a test that
 * asserted on English would have to be rewritten the first time a copy editor
 * touched a tooltip.
 */
export const GATE = {
  noFile: "gate.noFile",
  unknownFormat: "gate.unknownFormat",
  noPassword: "gate.noPassword",
  noPreview: "gate.noPreview",
  nothingTicked: "gate.nothingTicked",
  busy: "gate.busy",
  committed: "gate.committed",
  ahead: "gate.ahead",
} as const;

/** One of {@link GATE}'s keys — a key in the `import` catalogue, not a sentence. */
export type GateKey = (typeof GATE)[keyof typeof GATE];

/**
 * Why the wizard cannot move forward from `step`, or `null` when it can.
 *
 * Steps 3 and 7 have no forward gate: the wizard is doing the work, and the
 * only thing that moves it on is the work finishing.
 */
export function forwardBlock(step: StepNumber, facts: WizardFacts): GateKey | null {
  if (facts.busy) return GATE.busy;
  switch (step) {
    case 1:
      if (!facts.hasFile) return GATE.noFile;
      // A path the core has not looked at yet is not blocked: reading it is
      // what the forward control does. Blocking it on the format detection has
      // not run would be a button that can never be pressed.
      if (!facts.detected) return null;
      if (facts.format === null) return GATE.unknownFormat;
      return null;
    case 2:
      if (!facts.hasFile || facts.format === null) return GATE.noFile;
      if (facts.passwordRequired && !facts.hasPassword) return GATE.noPassword;
      return null;
    case 3:
      return GATE.busy;
    case 4:
    case 5:
    case 6:
      if (!facts.hasPreview) return GATE.noPreview;
      if (facts.includedCount === 0) return GATE.nothingTicked;
      return null;
    case 7:
      return GATE.busy;
    case 8:
      return null;
  }
}

/**
 * Whether the rail may jump straight to `target`.
 *
 * A committed import is finished: its preview handle is spent in the core, so
 * every step that would act on one is closed rather than left to fail on the
 * first click.
 */
export function canGoTo(target: StepNumber, facts: WizardFacts): boolean {
  if (facts.busy) return false;
  if (facts.committed) return target === 8;
  switch (target) {
    case 1:
      return true;
    case 2:
      return facts.hasFile && facts.format !== null;
    case 3:
      // Parsing is entered by acting, never by clicking the rail — a jump here
      // would mean re-reading the file behind the user's back.
      return false;
    case 4:
    case 5:
    case 6:
    case 7:
      return facts.hasPreview;
    case 8:
      return false;
  }
}

/** Why the rail refuses a jump, for the step button's tooltip. */
export function jumpBlock(target: StepNumber, facts: WizardFacts): GateKey | null {
  if (canGoTo(target, facts)) return null;
  if (facts.busy) return GATE.busy;
  if (facts.committed) return GATE.committed;
  if (target === 2 && !facts.hasFile) return GATE.noFile;
  if (target >= 4 && !facts.hasPreview) return GATE.noPreview;
  return GATE.ahead;
}
