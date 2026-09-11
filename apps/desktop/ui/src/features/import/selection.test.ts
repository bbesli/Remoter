/**
 * The include/exclude rules, which are the ones that decide what lands in a
 * vault that cannot be un-imported.
 */

import { describe, expect, it } from "vitest";

import type { ImportNode } from "@/lib/ipc";

import {
  excludeNode,
  excludedRoots,
  includeNode,
  includedCounts,
  indexNodes,
  matchingIds,
  tickState,
  toggleNode,
} from "./selection";

function node(partial: Partial<ImportNode> & Pick<ImportNode, "id" | "name" | "kind">): ImportNode {
  return {
    parentId: null,
    sortOrder: 0,
    protocol: null,
    host: null,
    port: null,
    portInherited: false,
    username: null,
    domain: null,
    hasSecret: false,
    credentialInherited: false,
    gatewayHops: 0,
    customFields: 0,
    ...partial,
  };
}

/**
 *   Production            folder
 *     EU-West             folder
 *       web-01            connection, password, 2 gateway hops
 *       web-02            connection
 *     svc-deploy          credential
 *   Archive 2019          folder
 *     old-01              connection
 */
const NODES: ImportNode[] = [
  node({ id: "prod", name: "Production", kind: "folder" }),
  node({ id: "eu", name: "EU-West", kind: "folder", parentId: "prod", sortOrder: 0 }),
  node({
    id: "web1",
    name: "web-01",
    kind: "connection",
    parentId: "eu",
    sortOrder: 0,
    host: "web-01.eu-west.acme",
    port: 22,
    username: "svc-deploy",
    hasSecret: true,
    gatewayHops: 2,
  }),
  node({
    id: "web2",
    name: "web-02",
    kind: "connection",
    parentId: "eu",
    sortOrder: 1,
    host: "web-02.eu-west.acme",
  }),
  node({ id: "cred", name: "svc-deploy", kind: "credential", parentId: "prod", sortOrder: 1 }),
  node({ id: "archive", name: "Archive 2019", kind: "folder", sortOrder: 1 }),
  node({ id: "old1", name: "old-01", kind: "connection", parentId: "archive", host: "old.acme" }),
];

const index = indexNodes(NODES, "en");

describe("indexNodes", () => {
  it("orders the tree depth-first, with depths", () => {
    expect([...index.order]).toEqual(["prod", "eu", "web1", "web2", "cred", "archive", "old1"]);
    expect(index.depth.get("web1")).toBe(2);
    expect(index.depth.get("archive")).toBe(0);
  });

  it("treats a node whose parent is missing as a root rather than hiding it", () => {
    const orphaned = indexNodes(
      [node({ id: "a", name: "a", kind: "connection", parentId: "gone" })],
      "en",
    );
    expect([...orphaned.order]).toEqual(["a"]);
    expect(orphaned.depth.get("a")).toBe(0);
  });

  it("does not spin on a parent cycle", () => {
    const cyclic = indexNodes(
      [
        node({ id: "a", name: "a", kind: "folder", parentId: "b" }),
        node({ id: "b", name: "b", kind: "folder", parentId: "a" }),
      ],
      "en",
    );
    expect([...cyclic.order].sort()).toEqual(["a", "b"]);
  });
});

describe("excluding", () => {
  it("takes the whole subtree with a folder", () => {
    const excluded = excludeNode(new Set(), index, "eu");
    expect([...excluded].sort()).toEqual(["eu", "web1", "web2"]);
    expect(tickState(excluded, index, "web1")).toBe("off");
    expect(tickState(excluded, index, "prod")).toBe("partial");
    expect(tickState(excluded, index, "archive")).toBe("on");
  });

  it("leaves nothing includable under an excluded folder", () => {
    const excluded = includeNode(excludeNode(new Set(), index, "prod"), index, "web1");
    // Re-ticking the connection re-ticks the folders above it, because the core
    // would otherwise drop the folder and the connection with it.
    expect(excluded.has("prod")).toBe(false);
    expect(excluded.has("eu")).toBe(false);
    expect(excluded.has("web1")).toBe(false);
    // Its siblings stay unticked.
    expect(excluded.has("web2")).toBe(true);
    expect(tickState(excluded, index, "prod")).toBe("partial");
  });

  it("toggles back to where it started", () => {
    const off = toggleNode(new Set(), index, "archive");
    const on = toggleNode(off, index, "archive");
    expect([...on]).toEqual([]);
    expect(tickState(on, index, "archive")).toBe("on");
  });
});

describe("includedCounts", () => {
  it("counts what is still ticked, by kind", () => {
    expect(includedCounts(index, new Set())).toEqual({
      folders: 3,
      connections: 3,
      credentials: 1,
      secrets: 1,
      gateways: 1,
      total: 7,
    });
  });

  it("drops a whole unticked subtree from the counts", () => {
    const excluded = excludeNode(new Set(), index, "archive");
    const counts = includedCounts(index, excluded);
    expect(counts.folders).toBe(2);
    expect(counts.connections).toBe(2);
    expect(counts.total).toBe(5);
  });

  it("counts the gateway chains, which is the thing the preview must not hide", () => {
    expect(includedCounts(index, new Set()).gateways).toBe(1);
    expect(includedCounts(index, excludeNode(new Set(), index, "web1")).gateways).toBe(0);
  });
});

describe("excludedRoots", () => {
  it("sends only the topmost excluded node of a subtree", () => {
    const excluded = excludeNode(new Set(), index, "eu");
    expect(excludedRoots(index, excluded)).toEqual(["eu"]);
  });

  it("sends each excluded subtree once", () => {
    const excluded = excludeNode(excludeNode(new Set(), index, "eu"), index, "archive");
    expect(excludedRoots(index, excluded).sort()).toEqual(["archive", "eu"]);
  });

  it("is empty when everything is ticked", () => {
    expect(excludedRoots(index, new Set())).toEqual([]);
  });
});

describe("matchingIds", () => {
  it("is null for an empty query, meaning no filter", () => {
    expect(matchingIds(index, "   ", "en")).toBeNull();
  });

  it("keeps a match, its ancestors and its subtree", () => {
    const visible = matchingIds(index, "web-01", "en");
    expect(visible).not.toBeNull();
    expect([...(visible ?? [])].sort()).toEqual(["eu", "prod", "web1"]);
  });

  it("matches on host and user, not only on name", () => {
    expect(matchingIds(index, "old.acme", "en")?.has("old1")).toBe(true);
    expect(matchingIds(index, "svc-deploy", "en")?.has("web1")).toBe(true);
  });

  it("shows everything under a matching folder", () => {
    const visible = matchingIds(index, "archive", "en");
    expect([...(visible ?? [])].sort()).toEqual(["archive", "old1"]);
  });
});

/**
 * The filter, in the languages whose alphabet English does not cover.
 *
 * An import file is very often a colleague's export, in the colleague's own
 * language, so this screen is where a wrong fold is met first and by the most
 * people. The preview can run to hundreds of rows, and a filter that cannot
 * find a machine by the name printed on it is how a row gets imported that the
 * user meant to untick.
 */
describe("matchingIds, outside English", () => {
  const FOREIGN: ImportNode[] = [
    // The host is deliberately not a transliteration of the name: the name has
    // to be reachable on its own, or the test passes on the host by accident.
    node({ id: "tr", name: "IŞIK-01", kind: "connection", host: "ws-901.kurum.tr" }),
    node({ id: "de", name: "Straße-Gateway", kind: "connection", host: "strasse.example.de" }),
    node({ id: "el", name: "ΟΔΟΣ-7", kind: "connection", host: "odos-7.example.gr" }),
    node({ id: "ar", name: "مُحَمَّد-01", kind: "connection", host: "m01.example.sa" }),
  ];
  const foreign = indexNodes(FOREIGN, "tr");

  it("finds a Turkish machine by the name written on it", () => {
    // The defect this replaces: "IŞIK-01" folded to "isik-01" under English
    // casing while the query "ışık" folded to "ısık", so the row was
    // unreachable by its own name.
    expect(matchingIds(foreign, "ışık", "tr")?.has("tr")).toBe(true);
  });

  it("finds it typed in capitals too", () => {
    expect(matchingIds(foreign, "IŞIK", "tr")?.has("tr")).toBe(true);
  });

  it("finds a German host by the two-letter spelling of its sharp s", () => {
    expect(matchingIds(foreign, "strasse", "de")?.has("de")).toBe(true);
    expect(matchingIds(foreign, "Straße", "de")?.has("de")).toBe(true);
  });

  it("finds a Greek name whichever sigma the reader typed", () => {
    expect(matchingIds(foreign, "οδός", "el")?.has("el")).toBe(true);
    expect(matchingIds(foreign, "ΟΔΟΣ", "el")?.has("el")).toBe(true);
  });

  it("finds an Arabic name without its vowel marks", () => {
    expect(matchingIds(foreign, "محمد", "ar")?.has("ar")).toBe(true);
  });

  it("still refuses a query that matches nothing", () => {
    expect([...(matchingIds(foreign, "zzz", "tr") ?? [])]).toEqual([]);
  });
});

/**
 * The other half of the same rule, and the regression that came with the first
 * half: a hostname is not a word in anyone's language.
 *
 * Folding one under the reader's rules breaks it in the direction nobody
 * expects — Turkish folds `VDI` to `vdı`, so the reader who types the letters
 * printed on the machine is told the file has no such host. The observed
 * defect, on an interface set to Turkish and a file of perfectly ordinary
 * corporate hostnames.
 */
describe("matchingIds, on identifiers rather than words", () => {
  const HOSTS: ImportNode[] = [
    node({ id: "gw", name: "Berlin gateway", kind: "connection", host: "VDI-GW.corp" }),
    node({ id: "api", name: "Avrupa", kind: "connection", host: "API-EU-01.corp" }),
    node({ id: "acct", name: "Yönetici", kind: "connection", host: "h9.corp", username: "ADMIN" }),
  ];
  const hosts = indexNodes(HOSTS, "tr");

  it("finds a host by its own letters with the interface in Turkish", () => {
    expect(matchingIds(hosts, "vdi", "tr")?.has("gw")).toBe(true);
    expect(matchingIds(hosts, "api", "tr")?.has("api")).toBe(true);
  });

  it("finds it typed in capitals too", () => {
    expect(matchingIds(hosts, "VDI", "tr")?.has("gw")).toBe(true);
  });

  it("folds an account name the same way a host is folded", () => {
    expect(matchingIds(hosts, "admin", "tr")?.has("acct")).toBe(true);
  });

  it("still folds the name in the reader's language", () => {
    // "Yönetici" is a word, and the name half of the row is what carries it.
    expect(matchingIds(hosts, "YÖNETİCİ", "tr")?.has("acct")).toBe(true);
  });
});

describe("indexNodes ordering", () => {
  it("orders siblings by the reader's collation, not the machine's", () => {
    // Turkish treats the dotless i as a letter of its own, sorted before the
    // dotted one, so "ısı" comes before "inek"; every other collation here
    // makes them the same letter and decides on the second character, which
    // puts "inek" first. Bare `localeCompare` answers with whatever language
    // the operating system is set to — which is how one file came out in two
    // orders on two laptops running the same build in the same language.
    const names: ImportNode[] = [
      node({ id: "dotless", name: "ısı", kind: "folder", sortOrder: 0 }),
      node({ id: "dotted", name: "inek", kind: "folder", sortOrder: 0 }),
    ];
    expect([...indexNodes(names, "tr").order]).toEqual(["dotless", "dotted"]);
    expect([...indexNodes(names, "en").order]).toEqual(["dotted", "dotless"]);
  });
});
