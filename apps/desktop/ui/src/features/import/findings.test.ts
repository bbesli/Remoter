/**
 * The findings a Remoter export produces, read as sentences.
 *
 * The describer is a switch over the core's finding kinds; a kind that reaches
 * it without a branch renders as nothing. These pin the branches Remoter's own
 * formats depend on, through the real English catalogue.
 */

import { beforeAll, describe, expect, it } from "vitest";
import type { TFunction } from "i18next";

import { i18n } from "@/i18n";
import type { ImportFinding } from "@/lib/ipc";

import { describeFinding } from "./findings";

let t: TFunction<"import">;

beforeAll(async () => {
  await i18n().loadNamespaces(["import"]);
  t = i18n().getFixedT("en", "import") as TFunction<"import">;
});

describe("describeFinding", () => {
  it("says how many credentials arrive without their secrets, and what that means", () => {
    const finding: ImportFinding = { severity: "warning", kind: "secrets_not_carried", count: 3 };
    const view = describeFinding(t, finding);
    expect(view.severity).toBe("warning");
    expect(view.title).toBe("3 credentials arrive without their passwords or keys.");
    expect(view.body).toMatch(/asks for its password or key the first time it is used/);
  });

  it("uses the singular for one", () => {
    const view = describeFinding(t, { severity: "warning", kind: "secrets_not_carried", count: 1 });
    expect(view.title).toBe("1 credential arrives without its password or key.");
  });

  it("says a password Windows protected stayed behind, and what happens instead", () => {
    const view = describeFinding(t, {
      severity: "warning",
      kind: "protected_passwords_not_carried",
      count: 2,
    });
    expect(view.title).toBe("2 saved passwords stay behind with Windows.");
    expect(view.body).toMatch(/asks for its password the first time it is used/);
  });

  it("names the gateway a connection will no longer go through", () => {
    const view = describeFinding(t, {
      severity: "warning",
      kind: "rd_gateway_not_supported",
      item: "Billing",
      host: "rdgw.example.com",
    });
    expect(view.title).toContain("Billing");
    expect(view.code).toBe("rdgw.example.com");
  });

  it("names the proxy a PuTTY session will no longer go through", () => {
    const view = describeFinding(t, {
      severity: "warning",
      kind: "proxy_not_supported",
      item: "app",
      proxy: "socks5",
      host: "socks.example.com",
    });
    expect(view.title).toContain("app");
    expect(view.body).toMatch(/never its password/);
    expect(view.code).toBe("socks5 socks.example.com");
  });

  it("names the credential profile the file does not contain", () => {
    const view = describeFinding(t, {
      severity: "warning",
      kind: "credential_profile_missing",
      item: "Payroll",
      profile: "Helpdesk",
    });
    expect(view.title).toContain("Helpdesk");
    expect(view.title).toContain("Payroll");
  });
});
