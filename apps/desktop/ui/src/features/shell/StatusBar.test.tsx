/**
 * The one line that says why nothing is connecting.
 *
 * The bar is where a refused resolution is met: the inspector holds the whole
 * failure and is closed by default, so for most users this sentence is the
 * entire explanation. It used to be the core's English `message`, rendered
 * straight into a bar whose every other word was translated — so on the one
 * screen where a user most needs their own language, they got none of it.
 */

import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { i18n } from "@/i18n";
import type { IpcFailure, TreeNode } from "@/lib/ipc";

import { StatusBar } from "./StatusBar";

/**
 * The Turkish sentences expected below, read off the shipped catalogue rather
 * than pasted in — a translator rewording one must not leave this file passing
 * against words no screen shows.
 */
const TR_ERRORS = Object.values(
  import.meta.glob("../../../../../../locales/tr/errors.json", {
    eager: true,
    import: "default",
  }) as Record<string, { vault: { locked: { message: string } } }>,
)[0];

const TURKISH_LOCKED = TR_ERRORS?.vault.locked.message ?? "";

const FAILURE: IpcFailure = {
  code: "vault.locked",
  message: "No vault is open. Unlock one to see your connections.",
  detail: "vault handle closed",
  actions: ["Unlock a vault"],
};

function node(): TreeNode {
  return {
    id: "conn-1",
    parentId: null,
    sortOrder: 0,
    kind: "connection",
    name: "web-01",
    description: "",
    tags: [],
    colour: null,
    protocol: "ssh",
    host: "web-01.example",
    port: 22,
    username: null,
    secretKind: null,
    keyFormat: null,
    hasPassphrase: false,
    agentCommentFilter: null,
    credentialId: null,
    attachedCredentialId: null,
    gateway: null,
    attachedTo: null,
    credentialChange: null,
    inheritedFieldCount: 0,
    updatedAt: 0,
  };
}

afterEach(async () => {
  await act(async () => {
    await i18n().changeLanguage("en");
  });
});

describe("the status bar's failure line", () => {
  it("shows the core's own sentence in English", () => {
    // English is served from the core, not from the catalogue: the core's
    // sentence carries specifics the generalised catalogue entry cannot.
    render(<StatusBar node={node()} effective={undefined} resolving={false} error={FAILURE} />);
    expect(screen.getByText(FAILURE.message)).toBeInTheDocument();
  });

  it("shows it in Turkish to a Turkish reader", async () => {
    await act(async () => {
      await i18n().changeLanguage("tr");
      // Catalogues load per namespace and on demand; awaiting them is what
      // makes "still English" a failure rather than a race.
      await i18n().loadNamespaces(["shell", "common", "errors"]);
    });

    render(<StatusBar node={node()} effective={undefined} resolving={false} error={FAILURE} />);

    expect(screen.getByText(TURKISH_LOCKED)).toBeInTheDocument();
    expect(screen.queryByText(/No vault is open/)).not.toBeInTheDocument();
  });

  it("keeps the sentence and its tooltip the same words", async () => {
    // Two renderings of one failure that can disagree is how a hover says one
    // thing and the line says another.
    await act(async () => {
      await i18n().changeLanguage("tr");
      await i18n().loadNamespaces(["shell", "common", "errors"]);
    });

    render(<StatusBar node={node()} effective={undefined} resolving={false} error={FAILURE} />);

    expect(screen.getByTitle(TURKISH_LOCKED)).toBeInTheDocument();
  });
});
