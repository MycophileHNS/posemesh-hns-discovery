import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { discoverPosemesh } from "../src/discover.ts";
import { MockResolver } from "../src/resolvers.ts";
import type { PosemeshManifest } from "../src/types.ts";

const fixedNow = new Date("2026-05-11T00:00:00.000Z");

describe("discoverPosemesh", () => {
  it("returns normalized discovery output from TXT and manifest data", async () => {
    const resolver = new MockResolver({
      "hq.posemesh": [
        "posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=TXT_KEY; capabilities=domain-discovery,relay-discovery",
      ],
    });
    const manifest: PosemeshManifest = {
      version: 1,
      sourceName: "hq.posemesh",
      domainManagers: [
        {
          id: "manager-1",
          endpoint: "https://hq.example.com/domain-manager",
          publicKey: "MANAGER_KEY",
          capabilities: ["domain-discovery"],
        },
      ],
      relays: [
        {
          id: "relay-1",
          endpoint: "wss://hq.example.com/relay",
          transport: "wss",
          publicKey: "RELAY_KEY",
        },
      ],
      bootstrapNodes: [
        {
          id: "bootstrap-1",
          endpoint: "https://hq.example.com/bootstrap",
          transport: "https",
        },
      ],
      publicKeys: ["MANIFEST_KEY"],
      capabilities: ["regional-bootstrap"],
    };

    const result = await discoverPosemesh("hq.posemesh", {
      resolver,
      now: () => fixedNow,
      manifestFetcher: async () => manifest,
    });

    assert.equal(result.name, "hq.posemesh");
    assert.equal(result.sourceName, "hq.posemesh");
    assert.equal(result.manifestUrl, "https://example.com/posemesh.json");
    assert.equal(result.resolvedAt, fixedNow.toISOString());
    assert.equal(result.domainManagers.length, 1);
    assert.equal(result.relays.length, 1);
    assert.equal(result.bootstrapNodes.length, 1);
    assert.deepEqual(result.publicKeys, [
      "TXT_KEY",
      "MANIFEST_KEY",
      "MANAGER_KEY",
      "RELAY_KEY",
    ]);
    assert.deepEqual(result.capabilities, [
      "domain-discovery",
      "relay-discovery",
      "regional-bootstrap",
    ]);
  });

  it("rejects non-.posemesh names by default", async () => {
    await assert.rejects(
      () => discoverPosemesh("not-posemesh.hns", {
        resolver: new MockResolver({}),
      }),
      /\.posemesh/,
    );
  });

  it("can skip manifest fetching for TXT-only output", async () => {
    const result = await discoverPosemesh("relays.posemesh", {
      resolver: new MockResolver({
        "relays.posemesh": [
          "posemesh:v1; manifest=https://example.com/relays.json; publicKey=TXT_KEY; capabilities=relay-discovery",
        ],
      }),
      fetchManifest: false,
      now: () => fixedNow,
    });

    assert.equal(result.manifestUrl, "https://example.com/relays.json");
    assert.deepEqual(result.relays, []);
    assert.deepEqual(result.publicKeys, ["TXT_KEY"]);
    assert.deepEqual(result.capabilities, ["relay-discovery"]);
  });
});
