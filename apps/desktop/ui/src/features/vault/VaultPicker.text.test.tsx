/**
 * The picker's two composed sentences, in the reader's language.
 *
 * This is the first screen of the application. It is read before anything has
 * been unlocked, which makes it the worst place in the product for English to
 * leak through — and it was leaking two whole paragraphs: why a remembered
 * vault cannot be opened, and the warning that a vault is sitting in a
 * cloud-sync folder. The core composed both and the picker printed them.
 *
 * What is asserted here is not the wording, which belongs to the translator.
 * It is that the English the core sent is *not* what reaches the screen, and
 * that the values inside the sentence — the path, the provider, the operating
 * system's own diagnostic — survive being moved into the catalogue's word
 * order.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { i18n } from "@/i18n/instance";
import { SOURCE_LOCALE, useT } from "@/i18n";
import type { RecentVault } from "@/lib/ipc";
import { withoutBidi } from "@/test/bidi";

import { syncWarningText, useUnreachableText } from "./VaultPicker";

const instance = i18n();

async function switchTo(code: string) {
  await act(async () => {
    await instance.changeLanguage(code);
    await instance.loadNamespaces(["vault", "errors"]);
  });
}

afterEach(async () => {
  await switchTo(SOURCE_LOCALE);
});

/** A remembered vault that is present but unreachable, with nothing composed. */
function vault(overrides: Partial<RecentVault> = {}): RecentVault {
  return {
    path: "/home/ada/work.rvault",
    label: "Work",
    lastOpened: null,
    slots: ["password"],
    reachable: false,
    unreachableReason: null,
    unreachableKind: null,
    unreachableDetail: null,
    unreachableCode: null,
    syncWarning: null,
    syncProvider: null,
    sizeBytes: null,
    ...overrides,
  };
}

function Line({ recent }: { recent: RecentVault }) {
  return <p>{useUnreachableText(recent)}</p>;
}

function line(): string {
  return withoutBidi(screen.getByRole("paragraph").textContent ?? "");
}

const MISSING = vault({
  unreachableKind: "missing",
  unreachableReason:
    "/home/ada/work.rvault is not there. If it is on a removable drive or a network share, connect it and try again.",
});

describe("why a vault cannot be reached", () => {
  it("is in the language the reader chose, not the core's English", async () => {
    await switchTo("tr");
    render(<Line recent={MISSING} />);
    expect(line()).not.toBe(MISSING.unreachableReason);
    // Still a sentence, and still about this vault.
    expect(line()).not.toBe("");
    expect(line()).toContain("/home/ada/work.rvault");
  });

  it("keeps the operating system's diagnostic verbatim", async () => {
    await switchTo("tr");
    const detail = "Permission denied (os error 13)";
    render(
      <Line
        recent={vault({
          unreachableKind: "unreadable",
          unreachableDetail: detail,
          unreachableReason: `/home/ada/work.rvault could not be read: ${detail}.`,
        })}
      />,
    );
    // The diagnostic is what a reader copies into a bug report; a translated
    // one is no use to whoever reads that report.
    expect(line()).toContain(detail);
  });

  it("shows the core's own sentence to an English reader", async () => {
    // The core's English is the catalogue's sentence with the specifics
    // already in it, so an English reader is no worse off — and this is the
    // path that proves the fallback is wired at all.
    render(<Line recent={MISSING} />);
    expect(line()).toContain("/home/ada/work.rvault");
  });

  it("falls back to the core's English for a kind it has never heard of", async () => {
    await switchTo("tr");
    const future = vault({
      // A kind added in Rust this morning. Cast because the union is the set
      // this build knows, and the point of the test is a value outside it.
      unreachableKind: "locked-by-another-process" as RecentVault["unreachableKind"],
      unreachableReason: "Another copy of Remoter has this vault open.",
    });
    render(<Line recent={future} />);
    expect(line()).toBe(future.unreachableReason);
  });

  it("renders a coded probe failure through the error catalogue", async () => {
    await switchTo("tr");
    // A file that is there but is not a vault arrives as an `IpcError` code,
    // because `errors.json` already has that sentence in every language.
    const corrupt = vault({
      unreachableCode: "vault.not-a-vault",
      unreachableReason: "/home/ada/work.rvault is not a Remoter vault.",
    });
    render(<Line recent={corrupt} />);
    expect(line()).not.toBe(corrupt.unreachableReason);
    expect(line()).not.toBe("");
  });

  it("says something even when the core sent no reason at all", async () => {
    await switchTo("tr");
    render(<Line recent={vault()} />);
    expect(line()).not.toBe("");
  });
});

// ------------------------------------------------------------ sync folder ---

function Warning({ recent }: { recent: RecentVault }) {
  const t = useT("vault");
  return <p>{syncWarningText(t, recent.syncProvider, recent.syncWarning)}</p>;
}

const ENGLISH_SYNC =
  "This vault is inside a Dropbox folder. It works, but editing it from two machines at once " +
  "will leave a conflict copy, and Dropbox keeps earlier versions of the encrypted file.";

describe("the cloud-sync warning", () => {
  it("is composed here, around a provider name that is never translated", async () => {
    await switchTo("tr");
    render(<Warning recent={vault({ syncProvider: "Dropbox", syncWarning: ENGLISH_SYNC })} />);
    expect(line()).not.toBe(ENGLISH_SYNC);
    expect(line()).toContain("Dropbox");
  });

  it("says nothing when the vault is not in a synced folder", () => {
    render(<Warning recent={vault()} />);
    expect(line()).toBe("");
  });

  it("falls back to the core's English when no provider crossed", async () => {
    // A core older than this build, or a provider it could not name.
    await switchTo("tr");
    render(<Warning recent={vault({ syncWarning: ENGLISH_SYNC })} />);
    expect(line()).toBe(ENGLISH_SYNC);
  });
});
