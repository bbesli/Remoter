/**
 * Tests for the guard.
 *
 * A lint rule with no tests is a rule that can stop matching without anything
 * failing — and this one's whole job is to fail. The cases below are the real
 * shapes this codebase used before extraction, plus the shapes that must stay
 * legal so the rule does not get switched off for being noisy.
 */

import { RuleTester } from "eslint";
import tsParser from "@typescript-eslint/parser";
import { afterAll, describe, it } from "vitest";

import plugin from "./i18n.js";

/*
 * RuleTester registers its own suite per case. It reaches for `describe` and
 * `it` as globals, and gets Mocha's semantics unless it is handed Vitest's —
 * without this it reports nothing, `ruleTester.run` resolves immediately, and
 * the file passes however wrong the rule is. It did, once, while a deliberately
 * broken case sat in the valid list.
 */
RuleTester.afterAll = afterAll;
RuleTester.describe = describe;
RuleTester.it = it;
RuleTester.itOnly = it.only;

const ruleTester = new RuleTester({
  languageOptions: {
    parser: tsParser,
    parserOptions: { ecmaVersion: 2022, sourceType: "module", ecmaFeatures: { jsx: true } },
  },
});

// RuleTester registers a suite per case at module load, so these calls are
// top-level rather than inside an it().
ruleTester.run("no-literal-jsx-text", plugin.rules["no-literal-jsx-text"], {
  valid: [
    { code: "const A = () => <p>{t('shell.main.lockedTitle')}</p>;" },
    { code: "const A = () => <p>{name}</p>;" },
    // Punctuation and separators the layout needs. A rule that flagged
    // these would be turned off within a week.
    { code: "const A = () => <span aria-hidden='true'>·</span>;" },
    { code: "const A = () => <span>—</span>;" },
    { code: "const A = () => <span>{count}</span>;" },
    // Attributes that are not user-visible.
    { code: "const A = () => <div className='row' data-state='idle' />;" },
    { code: "const A = () => <input type='password' name='remoter-locale' />;" },
    // A translated value in a visible attribute.
    { code: "const A = () => <button title={t('shell.titleBar.lock')} />;" },
    // Interpolation of data, not copy.
    { code: "const A = () => <span title={`${host}:${port}`} />;" },
    // Copy props holding a value rather than a literal. This is every one of
    // them in this codebase today, and it is why widening the attribute list
    // is safe: the rule reports literals, not prop names.
    { code: "const A = () => <Dialog lead={t('removeSlot.lead')} warning={warning} />;" },
    { code: "const A = () => <Boundary where={where} refusal={refusal} />;" },
    // A prop that ends in a copy word only by coincidence, in lower case.
    { code: "const A = () => <Field relabel='name' subtext={x} />;" },
  ],
  invalid: [
    {
      code: "const A = () => <p>Nothing selected</p>;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <p>{'Nothing selected'}</p>;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <button title='Lock the vault' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <button aria-label='Close the inspector' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <input placeholder='Filter by action or key' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      // The prop name a component uses for its own visible label.
      code: "const A = () => <Busy busyLabel='Saving…' retryLabel='Try again' />;",
      errors: [{ messageId: "hardcoded" }, { messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <p>{`Connected to ${host}`}</p>;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      // The probe that found the blind spot. Every one of these three props
      // draws words on screen and not one of them was in the attribute list,
      // so the whole element passed. Only empty strings were being passed on
      // the day it was noticed, which made the gap latent rather than absent —
      // it would have gone live the first time someone filled one in.
      code:
        "const A = () => <Widget heading='Recent vaults' emptyText='No vaults yet' " +
        "confirmLabel='Delete for ever' />;",
      errors: [
        { messageId: "hardcoded" },
        { messageId: "hardcoded" },
        { messageId: "hardcoded" },
      ],
        },
    {
      // The rest of the props this codebase uses for copy, in the shapes it
      // uses them in. Listing them individually is the point: a regression
      // that drops one from the attribute list should fail on that one line
      // rather than on a single case that covers all of them.
      code: "const A = () => <Notice body='Nothing to restore.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Busy note='This can take a minute.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Step footNote='Write it down now.' busyNote='Hashing…' />;",
      errors: [{ messageId: "hardcoded" }, { messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Bar unobservedNote='Nobody was watching.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Heading lead='Pick where the vault lives.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Slots warning='This is the last key slot.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Form error='That did not work.' dialogError='Neither did that.' />;",
      errors: [{ messageId: "hardcoded" }, { messageId: "hardcoded" }],
        },
    {
      code:
        "const A = () => <Dialog reason='The vault is locked.' " +
        "dismissBlockedReason='Still rotating the key.' />;",
      errors: [{ messageId: "hardcoded" }, { messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Slots refusal='The core would not do it.' />;",
      errors: [{ messageId: "hardcoded" }],
        },
    {
      code: "const A = () => <Boundary where='the connection tree' />;",
      errors: [{ messageId: "hardcoded" }],
        },
  ],
});

ruleTester.run("no-text-constant", plugin.rules["no-text-constant"], {
  valid: [
    // Not copy: identifiers, tokens, keys.
    { code: "const TEXT_KEYS = ['foreground', 'red'];" },
    { code: "const SIZES = { sm: 12, md: 16 };" },
    { code: "const KEYS = { title: 'shell.main.lockedTitle' };" },
    // A local map built from t(). This is the idiomatic shape after
    // extraction and must stay legal.
    {
      code: "function A() { const t = useT('shell'); const labels = { a: t('x') }; return labels; }",
        },
    // A module-level object that is not named like copy.
    { code: "const ROUTES = { home: 'The home screen' };" },
  ],
  invalid: [
    {
      code: "const TEXT = { title: 'This vault is empty' } as const;",
      errors: [{ messageId: "copyConstant" }],
        },
    {
      // The interpolating variant — exactly what ICU replaces.
      code: "const TEXT = { needsVault: (a) => `${a} needs an unlocked vault.` };",
      errors: [{ messageId: "copyConstant" }],
        },
    {
      code: "const TEXT = { promises: ['No telemetry of any kind.'] };",
      errors: [{ messageId: "copyConstant" }],
        },
    {
      code: "const COPY = { nested: { deep: 'Choose a credential' } };",
      errors: [{ messageId: "copyConstant" }],
        },
    {
      code: "const SIDEBAR_LABELS = { open: 'Show the connection tree' };",
      errors: [{ messageId: "copyConstant" }],
        },
  ],
});
