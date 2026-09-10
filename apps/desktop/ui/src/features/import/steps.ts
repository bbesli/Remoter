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

import type { ImportSource } from "@/lib/ipc";

export type StepNumber = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

export interface StepDefinition {
  n: StepNumber;
  label: string;
}

/**
 * The design's rail has "Conflicts" at 5. There is no conflict resolution in
 * the core — nothing compares an import against what is already in the vault —
 * so drawing that step would be a promise the wizard cannot keep. The report,
 * which the core does produce, takes the slot; the preview says plainly what
 * to do instead.
 */
export const STEPS: readonly StepDefinition[] = [
  { n: 1, label: "Source" },
  { n: 2, label: "Secrets" },
  { n: 3, label: "Parse" },
  { n: 4, label: "Preview" },
  { n: 5, label: "Report" },
  { n: 6, label: "Destination" },
  { n: 7, label: "Commit" },
  { n: 8, label: "Result" },
];

/** Everything the gates need to know, and nothing that would make them async. */
export interface WizardFacts {
  hasFile: boolean;
  /** What the file will be parsed as: detected, or chosen by the user. */
  format: ImportSource | null;
  /** Whether the detection on screen is the detection of the current path. */
  detected: boolean;
  passwordRequired: boolean;
  hasPassword: boolean;
  hasPreview: boolean;
  /** Nodes still ticked in the preview. Zero means there is nothing to write. */
  includedCount: number;
  committed: boolean;
  /** A detect, parse or commit is in flight. */
  busy: boolean;
}

export const GATE = {
  noFile: "Choose the file you want to import.",
  unknownFormat: "Remoter could not tell what this file is. Choose the format yourself.",
  noPassword: "This file needs its document password before it can be read.",
  noPreview: "Nothing has been read yet.",
  nothingTicked: "Everything is unticked. Tick at least one item to import.",
  busy: "Working…",
  committed: "This import has already been written. Start another one to import again.",
  ahead: "Finish the steps before this one first.",
} as const;

/**
 * Why the wizard cannot move forward from `step`, or `null` when it can.
 *
 * Steps 3 and 7 have no forward gate: the wizard is doing the work, and the
 * only thing that moves it on is the work finishing.
 */
export function forwardBlock(step: StepNumber, facts: WizardFacts): string | null {
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
export function jumpBlock(target: StepNumber, facts: WizardFacts): string | null {
  if (canGoTo(target, facts)) return null;
  if (facts.busy) return GATE.busy;
  if (facts.committed) return GATE.committed;
  if (target === 2 && !facts.hasFile) return GATE.noFile;
  if (target >= 4 && !facts.hasPreview) return GATE.noPreview;
  return GATE.ahead;
}
