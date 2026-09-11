/**
 * Failures, in the reader's language.
 *
 * The rules live in `failures.ts`; these are the ones that cost something if
 * they break. A code the catalogue knows must render the catalogue's words, or
 * the whole file is decoration. A code it does not know must render what the
 * core sent, because that is the only thing standing between a failure added
 * in Rust and a blank line where the sentence should be.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { FailureNotice } from "@/components/FailureNotice";

import { resolveFailureText, useFailureText, type CoreFailure } from "./failures";
import { i18n } from "./instance";
import { SOURCE_LOCALE } from "./locales";

const instance = i18n();

/**
 * A catalogue written here, so the resolution rules can be asserted without a
 * language, a catalogue file or a React tree. `read` throws for anything `has`
 * denied: nothing the core sent may be looked up, which is the property that
 * keeps a hostname containing `{` out of the ICU parser.
 */
function stub(entries: Record<string, string>, language = "tr") {
  return {
    language,
    has: (key: string) => key in entries,
    read: (key: string) => {
      const found = entries[key];
      if (found === undefined) throw new Error(`read("${key}") on a key that does not exist`);
      return found;
    },
  };
}

const LOCKED: CoreFailure = {
  code: "vault.locked",
  message: "No vault is open. Unlock one to see your connections.",
  detail: null,
  actions: ["Unlock a vault"],
};

describe("resolving a failure", () => {
  it("renders the catalogue for a code it knows", () => {
    const text = resolveFailureText(
      LOCKED,
      stub({
        "vault.locked.message": "Acik kasa yok.",
        "vault.locked.actions.0": "Bir kasanin kilidini ac",
      }),
    );
    expect(text.message).toBe("Acik kasa yok.");
    expect(text.actions).toEqual(["Bir kasanin kilidini ac"]);
  });

  it("renders what the core sent for a code it does not know", () => {
    // The case that matters most: a failure added in Rust this morning. It
    // shows up in English, which is right, rather than as a humanised key or an
    // empty callout.
    const added: CoreFailure = {
      code: "session.host-key-changed",
      message: "The host key for db-01 has changed since you last connected.",
      detail: "SHA256:abc",
      actions: ["Compare the fingerprints", "Cancel"],
    };
    expect(resolveFailureText(added, stub({}))).toEqual({
      message: added.message,
      detail: "SHA256:abc",
      actions: ["Compare the fingerprints", "Cancel"],
    });
  });

  it("never puts the core's own text through the catalogue", () => {
    // A message carries values the user or a remote host chose. One brace in a
    // file name would be ICU syntax if this were routed through `t()`, and the
    // reader would get the missing-key fallback instead of their error. `stub`
    // throws if a key that does not exist is read.
    const braced: CoreFailure = {
      code: "path.unusable",
      message: "/home/ada/{draft} cannot be used: it is not a directory.",
      detail: null,
      actions: ["#Choose another location"],
    };
    const text = resolveFailureText(braced, stub({}));
    expect(text.message).toBe(braced.message);
    expect(text.actions).toEqual(["#Choose another location"]);
  });

  it("relabels the actions it has and leaves the rest as sent", () => {
    // A translation that has not caught up with an action the core gained
    // shows that one in English rather than dropping a way out.
    const text = resolveFailureText(
      { ...LOCKED, actions: ["Unlock a vault", "Create a new vault"] },
      stub({ "vault.locked.actions.0": "Bir kasanin kilidini ac" }),
    );
    expect(text.actions).toEqual(["Bir kasanin kilidini ac", "Create a new vault"]);
  });

  it("labels an action from the shared lexicon when the entry has none", () => {
    // How every `session.*` action is translated: the failure's own entry has
    // no `actions`, because the core composes them and the order depends on
    // what actually failed, so the sentence itself is the key.
    const failed: CoreFailure = {
      code: "session.failed",
      message: "the server rejected these credentials (password)",
      detail: null,
      actions: ["Enter a credential for this attempt", "Choose a different credential"],
    };
    const text = resolveFailureText(
      failed,
      stub({
        "action.enter-credential": "Bu deneme için kimlik bilgisi gir",
        "action.choose-different-credential": "Başka bir kimlik bilgisi seç",
      }),
    );
    expect(text.actions).toEqual([
      "Bu deneme için kimlik bilgisi gir",
      "Başka bir kimlik bilgisi seç",
    ]);
    // No entry, so the core's own account of what happened survives.
    expect(text.message).toBe(failed.message);
  });

  it("prefers the entry's own label over the lexicon", () => {
    // A code that writes its own actions keeps its own wording: the lexicon is
    // the fallback for the ones that cannot, not a general override.
    const text = resolveFailureText(
      { ...LOCKED, code: "update.failed", actions: ["Try again"] },
      stub({ "update.failed.actions.0": "Guncelleme icin yeniden dene", "action.retry": "Yeniden dene" }),
    );
    expect(text.actions).toEqual(["Guncelleme icin yeniden dene"]);
  });

  it("labels an action the core moved, not the position it used to be in", () => {
    // `session.hop-failed` hands over the inner failure's actions when a hop
    // failed on the far end's identity, so position 0 is "edit the gateway
    // chain" on one path and "verify the fingerprint" on another. Labelling by
    // position would put the first name on the second button.
    const hop: CoreFailure = {
      code: "session.hop-failed",
      message: "Could not reach the target through `bastion-2`.",
      detail: null,
      actions: [
        "Verify the fingerprint with the server's administrator before doing anything else",
        "Contact the server's administrator",
      ],
    };
    const text = resolveFailureText(
      hop,
      stub({
        "action.verify-fingerprint-out-of-band": "Parmak izini once dogrula",
        "action.contact-server-administrator": "Sunucu yoneticisine basvur",
      }),
    );
    expect(text.actions).toEqual(["Parmak izini once dogrula", "Sunucu yoneticisine basvur"]);
  });

  it("passes the diagnostic through untouched", () => {
    // `detail` is an OS error string or a node id: what a reader copies into a
    // bug report, and useless to whoever reads that report once translated.
    const text = resolveFailureText(
      { ...LOCKED, code: "io.failed", detail: "Permission denied (os error 13)" },
      stub({ "io.failed.message": "O dosya okunamadi." }),
    );
    expect(text.detail).toBe("Permission denied (os error 13)");
  });

  it("lets a catalogue override the diagnostic when it deliberately has one", () => {
    const text = resolveFailureText(
      { ...LOCKED, detail: "node 41f2" },
      stub({ "vault.locked.detail": "Ayrinti" }),
    );
    expect(text.detail).toBe("Ayrinti");
  });

  it("serves English from the core, not from the catalogue", () => {
    // The core's sentence is the catalogue's with the specifics filled in —
    // "after 15 minutes", the actual path — and those cannot be recovered from
    // the finished string. Rendering the generalised English to an English
    // reader would take detail away for nothing.
    const specific: CoreFailure = {
      code: "vault.auto-locked",
      message: "The vault locked itself after 15 minutes without activity. Unlock it to carry on.",
      detail: null,
      actions: ["Unlock the vault"],
    };
    const text = resolveFailureText(
      specific,
      stub({ "vault.auto-locked.message": "Generalised English." }, SOURCE_LOCALE),
    );
    expect(text.message).toBe(specific.message);
  });

  it("refuses a code that is not a code", () => {
    // A key is a path. Something that can choose the separators could read
    // another namespace entirely, so anything that is not dotted lower-case
    // ASCII is answered from the core and never looked up.
    for (const code of ["", "errors:vault.locked", "../common.app.name", "Vault.Locked"]) {
      const text = resolveFailureText({ ...LOCKED, code }, stub({}));
      expect(text.message, code).toBe(LOCKED.message);
    }
  });
});

// ------------------------------------------------------- through i18next ---

function Notice({ failure }: { failure: CoreFailure }) {
  const text = useFailureText(failure);
  return (
    <>
      <p>{text.message}</p>
      {text.actions.map((action, index) => (
        <li key={index}>{action}</li>
      ))}
    </>
  );
}

async function switchTo(code: string) {
  await act(async () => {
    await instance.changeLanguage(code);
    await instance.loadNamespaces("errors");
  });
}

afterEach(async () => {
  await switchTo(SOURCE_LOCALE);
});

describe("a failure on screen", () => {
  it("is in the language the reader chose", async () => {
    await switchTo("tr");
    render(<Notice failure={LOCKED} />);

    // Not asserting the wording — that is the translator's to change. What is
    // asserted is that the English the core sent is NOT what reached the DOM.
    expect(screen.queryByText(LOCKED.message)).not.toBeInTheDocument();
    expect(screen.queryByText(LOCKED.actions[0] ?? "")).not.toBeInTheDocument();
    const rendered = screen.getByRole("paragraph");
    expect(rendered.textContent ?? "").not.toBe("");
  });

  it("falls back to the core's English for a code no catalogue has", async () => {
    // The code below is deliberately one the core does not send and the
    // catalogue therefore never holds. This test used to name a real code that
    // had not been translated yet, which made translating it look like a
    // regression: the assertion is about the *rule*, not about which failures
    // happen to be outstanding this week.
    await switchTo("tr");
    const unknown: CoreFailure = {
      code: "sftp.not-a-code-the-core-sends",
      message: "A transfer is still running in that pane.",
      detail: null,
      actions: ["Wait for it to finish"],
    };
    render(<Notice failure={unknown} />);
    expect(screen.getByText(unknown.message)).toBeInTheDocument();
    expect(screen.getByText("Wait for it to finish")).toBeInTheDocument();
  });

  it("translates a connection failure's buttons through the real catalogue", async () => {
    // The surface this whole file exists for: a rejected password, in Turkish,
    // with the sentence and both buttons coming out of `errors.json`. The
    // actions are the ones `action_text` produces, so they resolve through the
    // shared lexicon rather than through `session.auth-rejected`'s own entry.
    await switchTo("tr");
    const rejected: CoreFailure = {
      code: "session.auth-rejected",
      message: "The server rejected these credentials (password).",
      detail: null,
      actions: ["Enter a credential for this attempt", "Choose a different credential"],
    };
    render(<Notice failure={rejected} />);
    expect(screen.queryByText(rejected.message)).not.toBeInTheDocument();
    for (const action of rejected.actions) {
      expect(screen.queryByText(action)).not.toBeInTheDocument();
    }
    const buttons = screen.getAllByRole("listitem");
    expect(buttons).toHaveLength(2);
    for (const button of buttons) expect(button.textContent ?? "").not.toBe("");
  });

  it("shows the core's own sentence in English", async () => {
    render(<Notice failure={LOCKED} />);
    expect(screen.getByText(LOCKED.message)).toBeInTheDocument();
  });
});

describe("the notice every screen uses", () => {
  // `FailureNotice` is the only place most failures are ever drawn, so the
  // wiring is worth pinning here rather than trusting: it rendered `message`,
  // `detail` and every action straight from the core for a milestone, and
  // nothing about that looks wrong on an English machine.
  it("draws the translated text, not the core's", async () => {
    await switchTo("tr");
    render(<FailureNotice failure={{ ...LOCKED, actions: [...LOCKED.actions] }} />);
    expect(screen.queryByText(LOCKED.message)).not.toBeInTheDocument();
    expect(screen.queryByText(LOCKED.actions[0] ?? "")).not.toBeInTheDocument();
    expect(screen.getByRole("listitem").textContent ?? "").not.toBe("");
  });
});
