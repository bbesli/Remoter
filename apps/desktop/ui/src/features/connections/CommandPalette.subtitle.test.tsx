/**
 * The second line of a search hit, in the reader's language.
 *
 * The core used to send this finished: `"1 item"`, `"12 members"`, pluralised
 * with an `if (count == 1)` and written in ASCII digits, and the palette
 * printed it verbatim. That is wrong three times over in the languages this
 * ships in — Russian has four plural categories and Arabic six, so "12 items"
 * is not a form either language has; and a reader whose locale uses another
 * numbering system gets Latin digits inside their own script.
 *
 * The wording is the translator's. What is asserted here is that the English
 * the core sent is not what reaches the screen, that the number does, and that
 * a hit whose subtitle is a *value* — an address, a login — is left alone.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { i18n } from "@/i18n/instance";
import { SOURCE_LOCALE, useT } from "@/i18n";
import type { SearchHit, TreeNode } from "@/lib/ipc";

import { subtitleText } from "./CommandPalette";

const instance = i18n();

async function switchTo(code: string) {
  await act(async () => {
    await instance.changeLanguage(code);
    await instance.loadNamespaces("connections");
  });
}

afterEach(async () => {
  await switchTo(SOURCE_LOCALE);
});

/** Only the fields `subtitleText` reads are meaningful; the rest is scaffolding. */
function hit(overrides: Partial<SearchHit>): SearchHit {
  const node = {
    id: "n1",
    parentId: null,
    kind: "folder",
    name: "Datacentre",
    tags: [],
  } as unknown as TreeNode;
  return {
    node,
    path: "",
    nameMatches: [],
    subtitle: "",
    subtitleKind: null,
    subtitleCount: null,
    score: 1,
    ...overrides,
  };
}

function Subtitle({ search }: { search: SearchHit }) {
  const t = useT("connections");
  return <p>{subtitleText(t, search)}</p>;
}

function line(): string {
  return screen.getByRole("paragraph").textContent ?? "";
}

describe("a counted subtitle", () => {
  it("is composed from the catalogue, not printed as the core sent it", async () => {
    await switchTo("tr");
    const folder = hit({ subtitle: "12 items", subtitleKind: "items", subtitleCount: 12 });
    render(<Subtitle search={folder} />);
    expect(line()).not.toBe("12 items");
    expect(line()).toContain("12");
  });

  it("inflects for a language with more plural categories than English", async () => {
    // Russian has four. An English `if (count === 1)` has two, so it produces
    // a form the language does not have for at least half of all counts.
    await switchTo("ru");
    const forms = new Set<string>();
    for (const count of [1, 2, 5, 21]) {
      const { unmount } = render(
        <Subtitle search={hit({ subtitle: `${count} items`, subtitleKind: "items", subtitleCount: count })} />,
      );
      forms.add(line().replace(/\d+/g, "#"));
      unmount();
    }
    expect(forms.size).toBeGreaterThan(1);
  });

  it("counts members as well as items", async () => {
    await switchTo("tr");
    render(<Subtitle search={hit({ subtitle: "1 member", subtitleKind: "members", subtitleCount: 1 })} />);
    expect(line()).not.toBe("1 member");
    expect(line()).not.toBe("");
  });

  it("leaves a subtitle that is a value alone", () => {
    // An address is not language: there is nothing in "ssh://web1:22" for a
    // catalogue to say, and routing it through one would be an invitation to
    // translate a hostname.
    const connection = hit({ subtitle: "ssh://web1.example.com:22" });
    render(<Subtitle search={connection} />);
    expect(line()).toBe("ssh://web1.example.com:22");
  });

  it("falls back to the core's English for a kind it has never heard of", async () => {
    await switchTo("tr");
    const future = hit({
      subtitle: "3 sessions",
      // A kind added in Rust this morning; the cast is the point of the test.
      subtitleKind: "sessions" as SearchHit["subtitleKind"],
      subtitleCount: 3,
    });
    render(<Subtitle search={future} />);
    expect(line()).toBe("3 sessions");
  });

  it("treats a missing count as none rather than as no sentence", async () => {
    await switchTo("tr");
    render(<Subtitle search={hit({ subtitle: "0 items", subtitleKind: "items" })} />);
    expect(line()).not.toBe("");
  });
});
