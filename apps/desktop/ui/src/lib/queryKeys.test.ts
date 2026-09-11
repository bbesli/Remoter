/**
 * The boundary that decides what a lock takes off the screen.
 *
 * The rule under test is the direction of the default, not the contents of a
 * list. A boundary written as "clear these keys" is a boundary that is wrong
 * the first time somebody adds a query and forgets to come back to it — and
 * being wrong here means a folder tree left legible on an unattended machine.
 * So the test that matters is the one about a key nobody has written yet.
 */

import { QueryClient } from "@tanstack/react-query";
import { describe, expect, it } from "vitest";

import { auditKeys } from "@/features/audit/queryKeys";
import { vaultAdminKeys } from "@/features/vaultsettings/keys";

import { clearVaultScopedQueries, isVaultScoped, qk } from "./queryKeys";

describe("the vault-scoped boundary", () => {
  it("treats a key nobody has declared yet as vault data", () => {
    // The whole point. A feature added next month reads something out of the
    // vault under a key this file has never heard of; it is cleared anyway.
    expect(isVaultScoped(["some", "feature", "written", "later"])).toBe(true);
    expect(isVaultScoped([])).toBe(true);
  });

  it("covers everything read out of the open vault", () => {
    for (const key of [
      qk.nodes(),
      qk.resolve("n1"),
      qk.search("web"),
      qk.sessions(),
      qk.tunnels(),
      qk.sftpPane(1),
      qk.sftpListing(1, "/home/deploy"),
      qk.sftpListings(1),
      qk.sftpTransfers(1),
      qk.sftpStat(1, "/home/deploy/deploy.sh"),
      qk.sftpLinkTarget(1, "/home/deploy/current"),
      auditKeys.all(),
      auditKeys.page({} as Parameters<typeof auditKeys.page>[0]),
      // Shares the "vault" head with the survivors below and is still vault
      // data: the settings inside the file need the file open to be read.
      vaultAdminKeys.settings(),
      vaultAdminKeys.slots(),
    ]) {
      expect(isVaultScoped(key), key.join("/")).toBe(true);
    }
  });

  it("spares what a locked vault still needs", () => {
    for (const key of [
      // The fact of the lock itself.
      qk.vaultState(),
      // The cleartext header — the unlock screen's entire content.
      qk.vaultProbe("/vaults/work.rvault"),
      // This machine's own list, and this installation's preferences.
      qk.recentVaults(),
      qk.settings(),
      // Build constants.
      qk.protocolSchemas(),
      ["appVersion"],
    ]) {
      expect(isVaultScoped(key), key.join("/")).toBe(false);
    }
  });
});

describe("clearing on lock", () => {
  it("removes the vault's data and leaves the rest in place", () => {
    const client = new QueryClient();
    client.setQueryData(qk.nodes(), [{ id: "n1", name: "web-01" }]);
    client.setQueryData(qk.resolve("n1"), { host: "10.0.4.12" });
    client.setQueryData(qk.tunnels(), []);
    client.setQueryData(auditKeys.all(), []);
    client.setQueryData(vaultAdminKeys.slots(), []);
    client.setQueryData(qk.settings(), { locale: "tr" });
    client.setQueryData(qk.vaultProbe("/vaults/work.rvault"), { label: "Work" });

    clearVaultScopedQueries(client);

    expect(client.getQueryData(qk.nodes())).toBeUndefined();
    expect(client.getQueryData(qk.resolve("n1"))).toBeUndefined();
    expect(client.getQueryData(qk.tunnels())).toBeUndefined();
    expect(client.getQueryData(auditKeys.all())).toBeUndefined();
    expect(client.getQueryData(vaultAdminKeys.slots())).toBeUndefined();

    // `client.clear()` — which is what the lock button used to call — took
    // these too, so the reader's language and the header the unlock screen
    // draws itself from both went with the tree.
    expect(client.getQueryData(qk.settings())).toEqual({ locale: "tr" });
    expect(client.getQueryData(qk.vaultProbe("/vaults/work.rvault"))).toEqual({ label: "Work" });
  });
});
