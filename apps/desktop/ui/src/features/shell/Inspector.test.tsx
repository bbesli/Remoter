/**
 * The inspector's provenance lines.
 *
 * The username is the field people are most often surprised by — a connection
 * can log in as an account named two folders up — so it resolves with the
 * credential that holds it and shows that credential's source, like every
 * other inherited field. The credential itself needs one distinction the other
 * fields do not: "set here" is true both of a login this connection owns and
 * of a shared credential others use, and editing the second one changes what
 * they log in as.
 */

import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import type { EffectiveConnection, ResolvedField, TreeNode } from "@/lib/ipc";

import { Inspector } from "./Inspector";

function field(over: Partial<ResolvedField> & { field: string }): ResolvedField {
  return {
    value: null,
    origin: "own",
    sourceName: null,
    sourceId: null,
    overrides: null,
    ...over,
  };
}

const CONNECTION: TreeNode = {
  id: "conn-1",
  parentId: "folder-1",
  sortOrder: 0,
  kind: "connection",
  name: "web-01",
  description: "",
  tags: [],
  colour: null,
  protocol: "ssh",
  host: "web-01.eu.example.net",
  port: 22,
  username: null,
  secretKind: null,
  keyFormat: null,
  hasPassphrase: false,
  agentCommentFilter: null,
  credentialId: null,
  attachedCredentialId: null,
  attachedTo: null,
  credentialChange: null,
  inheritedFieldCount: 0,
  updatedAt: 0,
};

function show(effective: EffectiveConnection) {
  return render(
    <Inspector
      node={CONNECTION}
      effective={effective}
      loading={false}
      error={null}
      onClose={() => undefined}
    />,
  );
}

describe("the resolved username", () => {
  it("shows its value and the folder it came from", () => {
    show({
      nodeId: "conn-1",
      protocol: "ssh",
      fields: [
        field({
          field: "username",
          value: "svc-deploy",
          origin: "inherited",
          sourceName: "Datacentre EU-West",
          sourceId: "folder-1",
        }),
      ],
      gatewayChain: [],
      tags: [],
      credentialAttached: false,
    });

    expect(screen.getByText("username")).toBeInTheDocument();
    expect(screen.getByText("svc-deploy")).toBeInTheDocument();
    expect(screen.getByText("from Datacentre EU-West")).toBeInTheDocument();
  });
});

describe("where the credential comes from", () => {
  it("names a login the connection owns", () => {
    show({
      nodeId: "conn-1",
      protocol: "ssh",
      fields: [field({ field: "credential", value: "web-01", origin: "own" })],
      gatewayChain: [],
      tags: [],
      credentialAttached: true,
    });

    expect(screen.getByText("this connection's own")).toBeInTheDocument();
  });

  it("says a shared credential is shared, because editing it changes theirs", () => {
    show({
      nodeId: "conn-1",
      protocol: "ssh",
      fields: [field({ field: "credential", value: "svc-deploy", origin: "own" })],
      gatewayChain: [],
      tags: [],
      credentialAttached: false,
    });

    expect(screen.getByText(/shared with other entries/)).toBeInTheDocument();
  });
});
