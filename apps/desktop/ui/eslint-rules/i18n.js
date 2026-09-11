/**
 * The guard that stops the interface drifting back into hardcoded English.
 *
 * This matters more than any individual translation. Every string in this
 * frontend was hardcoded once, and it happened one file at a time, each time
 * for a good local reason — a label is quicker to type than a catalogue key,
 * and nothing complained. Extracting them without leaving something behind
 * that complains would only reset the clock.
 *
 * Two rules, because the problem has two shapes here:
 *
 *  - `no-literal-jsx-text` catches a string written straight into JSX, either
 *    as a text child or as a user-visible attribute.
 *  - `no-text-constant` catches the pattern this codebase actually reached
 *    for: a module-level `const TEXT = { … }` holding the file's copy, with
 *    JSX referring to `TEXT.title`. The first rule alone cannot see that —
 *    `{TEXT.title}` is an identifier, not a literal — and a guard that misses
 *    the exact habit it was written for is decoration.
 *
 * Escaping either one is the ordinary ESLint disable comment, with a reason:
 *
 *   {/* eslint-disable-next-line remoter-i18n/no-literal-jsx-text --
 *       protocol name, never translated (docs/features/i18n.md) *\/}
 *
 * Things that are legitimately not translated — protocol names, hostnames,
 * ports, file paths, version strings — are listed in docs/features/i18n.md
 * under "What is never translated". Every one of them is a defensible
 * disable; none of them is a reason to weaken the rule.
 */

/**
 * Does this string contain anything a reader would recognise as a word?
 *
 * Separators, arrows, bullets, colons and the like are punctuation the layout
 * needs, not copy. Requiring two adjacent letters rather than one keeps single
 * glyphs and units — `·`, `—`, `%`, `B` — out of the report while still
 * catching `OK` and `Go`.
 */
function looksLikeCopy(raw) {
  const text = raw.trim();
  if (text === "") return false;
  return /\p{L}\p{L}/u.test(text);
}

/** JSX attributes whose value is read aloud or drawn on screen. */
const VISIBLE_ATTRIBUTES = new Set([
  "alt",
  "aria-description",
  "aria-label",
  "aria-placeholder",
  "aria-roledescription",
  "aria-valuetext",
  "ariaLabel",
  "ariaValueText",
  "busyLabel",
  "caption",
  "description",
  "disabledReason",
  "help",
  "label",
  "placeholder",
  "retryLabel",
  "title",
]);

const MESSAGE =
  "This string is user-visible and is not translated. Move it to " +
  "locales/en/<namespace>.json and read it with t() from @/i18n. " +
  "See CLAUDE.md §6.";

const noLiteralJsxText = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Require user-visible strings in JSX to come from a translation catalogue.",
    },
    schema: [],
    messages: { hardcoded: MESSAGE },
  },
  create(context) {
    function reportIfCopy(node, value) {
      if (typeof value !== "string" || !looksLikeCopy(value)) return;
      context.report({ node, messageId: "hardcoded" });
    }

    return {
      JSXText(node) {
        reportIfCopy(node, node.value);
      },

      // `<span>{"Nothing selected"}</span>` and its template-literal cousin.
      JSXExpressionContainer(node) {
        const parentType = node.parent?.type;
        if (parentType !== "JSXElement" && parentType !== "JSXFragment") return;
        const expression = node.expression;
        if (expression.type === "Literal") {
          reportIfCopy(expression, expression.value);
        } else if (expression.type === "TemplateLiteral") {
          const flat = expression.quasis.map((q) => q.value.cooked ?? "").join(" ");
          reportIfCopy(expression, flat);
        }
      },

      JSXAttribute(node) {
        if (node.name.type !== "JSXIdentifier") return;
        if (!VISIBLE_ATTRIBUTES.has(node.name.name)) return;
        const value = node.value;
        if (value === null) return;
        if (value.type === "Literal") {
          reportIfCopy(value, value.value);
        } else if (
          value.type === "JSXExpressionContainer" &&
          value.expression.type === "Literal"
        ) {
          reportIfCopy(value.expression, value.expression.value);
        } else if (
          value.type === "JSXExpressionContainer" &&
          value.expression.type === "TemplateLiteral"
        ) {
          const flat = value.expression.quasis.map((q) => q.value.cooked ?? "").join(" ");
          reportIfCopy(value.expression, flat);
        }
      },
    };
  },
};

/** `TEXT`, `COPY`, `STRINGS`, `LABELS`, `MESSAGES`, `FOO_TEXT`, `TEXT_BAR`. */
const COPY_CONSTANT = /^(TEXT|COPY|STRINGS|LABELS|MESSAGES)$|_?(TEXT|COPY|STRINGS|LABELS|MESSAGES)_?/;

const CONSTANT_MESSAGE =
  "A module-level object of interface copy is a translation catalogue in the " +
  "wrong file. Move its strings to locales/en/<namespace>.json and read them " +
  "with t() from @/i18n. See CLAUDE.md §6.";

const noTextConstant = {
  meta: {
    type: "problem",
    docs: {
      description:
        "Forbid per-file copy constants, which hide user-visible strings from the JSX rule.",
    },
    schema: [],
    messages: { copyConstant: CONSTANT_MESSAGE },
  },
  create(context) {
    /** Any string leaf anywhere inside the object, however nested. */
    function containsCopy(node, depth = 0) {
      if (depth > 6 || node === null || node === undefined) return false;
      switch (node.type) {
        case "Literal":
          return typeof node.value === "string" && looksLikeCopy(node.value);
        case "TemplateLiteral":
          return looksLikeCopy(node.quasis.map((q) => q.value.cooked ?? "").join(" "));
        case "ObjectExpression":
          return node.properties.some(
            (p) => p.type === "Property" && containsCopy(p.value, depth + 1),
          );
        case "ArrayExpression":
          return node.elements.some((e) => containsCopy(e, depth + 1));
        // `notReady: (name) => \`${name} — not yet available\`` — the shape a
        // per-file TEXT constant reaches for when a string needs a value in it,
        // and the exact thing ICU interpolation replaces.
        case "ArrowFunctionExpression":
        case "FunctionExpression":
          return containsCopy(node.body, depth + 1);
        case "BlockStatement":
          return node.body.some(
            (s) => s.type === "ReturnStatement" && containsCopy(s.argument, depth + 1),
          );
        case "ConditionalExpression":
          return (
            containsCopy(node.consequent, depth + 1) || containsCopy(node.alternate, depth + 1)
          );
        case "TSAsExpression":
          return containsCopy(node.expression, depth + 1);
        default:
          return false;
      }
    }

    return {
      VariableDeclarator(node) {
        // Module scope only. A local `const labels = …` built from `t()` calls
        // is idiomatic and must stay legal.
        if (node.parent?.parent?.type !== "Program") return;
        if (node.id.type !== "Identifier" || !COPY_CONSTANT.test(node.id.name)) return;
        if (node.init === null || node.init === undefined) return;
        const init = node.init.type === "TSAsExpression" ? node.init.expression : node.init;
        if (init.type !== "ObjectExpression") return;
        if (!containsCopy(init)) return;
        context.report({ node: node.id, messageId: "copyConstant" });
      },
    };
  },
};

export default {
  meta: { name: "remoter-i18n" },
  rules: {
    "no-literal-jsx-text": noLiteralJsxText,
    "no-text-constant": noTextConstant,
  },
};
