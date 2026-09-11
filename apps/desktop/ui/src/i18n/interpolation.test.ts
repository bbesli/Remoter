/**
 * The property this whole layer stands on: an interpolated value is DATA.
 *
 * A hostname, a MOTD line, a directory entry and a remote error message all
 * reach translated strings, and all of them come from a machine the user does
 * not control. CLAUDE.md §6 says remote content is untrusted text. These tests
 * pin down what that means once a message formatter is between the value and
 * the screen — which is the part a refactor could quietly remove, because
 * nothing about the rendered output looks different when it breaks.
 */

import { describe, expect, it } from "vitest";

import { initI18n } from "./instance";

const i18n = initI18n();

/** A message with one argument, registered for the duration of the test file. */
function withMessage(key: string, message: string) {
  i18n.addResource("en", "common", key, message);
  return (values: Record<string, unknown>) => i18n.t(`common:${key}` as never, values) as string;
}

describe("interpolated values are substituted, never re-parsed", () => {
  it("does not treat braces in a value as message syntax", () => {
    const t = withMessage("test.host", "Connected to {host}");
    // A hostname is not allowed to contain braces, but a MOTD line, a file
    // name and a remote error message all are — and they reach the same
    // messages. If the value were re-parsed, this would throw or interpolate.
    expect(t({ host: "{host}" })).toBe("Connected to {host}");
    expect(t({ host: "{count, plural, other {#}}" })).toBe(
      "Connected to {count, plural, other {#}}",
    );
  });

  it("does not treat an unbalanced brace in a value as a broken message", () => {
    const t = withMessage("test.motd", "Banner: {line}");
    expect(t({ line: "welcome }{ back" })).toBe("Banner: welcome }{ back");
  });

  it("does not expand a value into a second argument", () => {
    const t = withMessage("test.two", "{a} then {b}");
    expect(t({ a: "{b}", b: "second" })).toBe("{b} then second");
  });

  it("leaves markup in a value alone", () => {
    const t = withMessage("test.markup", "Host: {host}");
    // React escapes this on the way to the DOM; what matters here is that the
    // formatter neither strips it, nor HTML-escapes it into visible entities.
    // Escaping twice would show the user `db&amp;01` for a host named `db&01`.
    expect(t({ host: "<script>alert(1)</script>" })).toBe("Host: <script>alert(1)</script>");
    expect(t({ host: "db&01" })).toBe("Host: db&01");
    expect(t({ host: "a<b>c" })).toBe("Host: a<b>c");
  });

  it("leaves a hash in a value alone, inside a plural clause", () => {
    const t = withMessage(
      "test.hashInPlural",
      "{count, plural, one {# file on {host}} other {# files on {host}}}",
    );
    expect(t({ count: 1, host: "#1" })).toBe("1 file on #1");
    expect(t({ count: 4, host: "#1" })).toBe("4 files on #1");
  });

  it("does not evaluate a value as a nested message even when it looks like one", () => {
    const t = withMessage("test.nested", "{outer}");
    expect(t({ outer: "{outer}" })).toBe("{outer}");
  });
});

describe("bidi isolation", () => {
  it("keeps the sentence's direction when a value carries its own", async () => {
    const { isolate } = await import("./bidi");
    const t = withMessage("test.bidiHost", "Connected to {host}");
    const rendered = t({ host: isolate("שרת-01") });
    expect(rendered.startsWith("Connected to \u2068")).toBe(true);
    expect(rendered.endsWith("\u2069")).toBe(true);
  });

  it("leaves an empty value alone rather than emitting two invisible characters", async () => {
    const { isolate } = await import("./bidi");
    expect(isolate("")).toBe("");
    expect(isolate("   ")).toBe("   ");
  });
});
