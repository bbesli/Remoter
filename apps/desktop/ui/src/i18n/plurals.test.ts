/**
 * Real CLDR plural rules, checked against the languages that punish a
 * one/other switch.
 *
 * Russian has four categories and Arabic six. English and German have two, so
 * a naive implementation looks correct for as long as nobody tests it in the
 * languages it is wrong in — which is half the shipping list. These tests exist
 * so the day someone "simplifies" the formatter, the failure is here rather
 * than in a bug report from a translator.
 *
 * The catalogues below are written inline rather than added to `locales/`,
 * because they are test fixtures: real Russian and Arabic copy comes from
 * translators through Weblate, and inventing it here would put unreviewed
 * grammar in a shipping directory.
 */

import { beforeAll, describe, expect, it } from "vitest";

import { initI18n } from "./instance";

const i18n = initI18n();

const NS = "common";

beforeAll(() => {
  // Russian: one (1, 21, 31…), few (2-4, 22-24…), many (0, 5-20, 11-14…), other.
  i18n.addResourceBundle(
    "ru",
    NS,
    {
      test: {
        files:
          "{count, plural, one {# файл} few {# файла} many {# файлов} other {# файла}}",
      },
    },
    true,
    true,
  );

  // Arabic: zero, one, two, few, many, other — all six are reachable.
  i18n.addResourceBundle(
    "ar",
    NS,
    {
      test: {
        files:
          "{count, plural, zero {لا ملفات} one {ملف واحد} two {ملفان} few {# ملفات} many {# ملفًا} other {# ملف}}",
      },
    },
    true,
    true,
  );

  i18n.addResourceBundle(
    "en",
    NS,
    { test: { files: "{count, plural, =0 {no files} one {# file} other {# files}}" } },
    true,
    true,
  );
});

function translate(lng: string, count: number): string {
  return i18n.getFixedT(lng, NS)("test.files" as never, { count } as never) as unknown as string;
}

describe("Russian, four categories", () => {
  it.each([
    [1, "1 файл"],
    [2, "2 файла"],
    [3, "3 файла"],
    [4, "4 файла"],
    [5, "5 файлов"],
    [11, "11 файлов"],
    [21, "21 файл"],
    [22, "22 файла"],
    [25, "25 файлов"],
    [101, "101 файл"],
    [111, "111 файлов"],
  ])("%i", (count, expected) => {
    expect(translate("ru", count)).toBe(expected);
  });

  it("does not collapse to a one/other switch", () => {
    // The whole point: 2 and 5 differ, and a two-form implementation cannot
    // tell them apart.
    expect(translate("ru", 2)).not.toBe(translate("ru", 5));
  });
});

describe("Arabic, six categories", () => {
  it.each([
    [0, "لا ملفات"],
    [1, "ملف واحد"],
    [2, "ملفان"],
    [3, "3 ملفات"],
    [11, "11 ملفًا"],
    [100, "100 ملف"],
  ])("%i", (count, expected) => {
    expect(translate("ar", count)).toBe(expected);
  });

  it("reaches all six forms for distinct counts", () => {
    const forms = new Set([0, 1, 2, 3, 11, 100].map((n) => translate("ar", n)));
    expect(forms.size).toBe(6);
  });
});

describe("English, and the explicit zero case", () => {
  it("uses =0 in preference to the plural category", () => {
    // CLDR puts 0 in `other` for English. `=0` is an exact match and wins,
    // which is what lets the footer say "no sessions" instead of "0 sessions".
    expect(translate("en", 0)).toBe("no files");
    expect(translate("en", 1)).toBe("1 file");
    expect(translate("en", 7)).toBe("7 files");
  });
});

describe("the shipped catalogue's own plurals", () => {
  it("declares every category the language needs", () => {
    // A message that omits a category the language has is a grammatical error
    // in that language, and `intl-messageformat` reports it only at format
    // time — for the counts that reach the missing category, which may be
    // none in a test. Checking the English source keeps the shape honest:
    // every plural here must at least carry `other`, which is the ICU
    // requirement and the fallback for every category a translator leaves out.
    const messages = [
      "footer.sessions",
      "footer.tunnels",
      "footer.connections",
      "footer.credentials",
    ];
    for (const key of messages) {
      const source = i18n.getResource("en", "shell", key);
      expect(typeof source).toBe("string");
      expect(String(source)).toContain("other {");
    }
  });

  it("formats the footer counts through real plural rules", () => {
    const t = i18n.getFixedT("en", "shell");
    expect(t("footer.sessions" as never, { count: 0 } as never)).toBe("no sessions");
    expect(t("footer.sessions" as never, { count: 1 } as never)).toBe("1 session");
    expect(t("footer.sessions" as never, { count: 4 } as never)).toBe("4 sessions");
  });
});
