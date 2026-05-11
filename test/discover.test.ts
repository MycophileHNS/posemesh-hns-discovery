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
      reconstructionNodes: [
        {
          id: "reconstruction-1",
          endpoint: "https://hq.example.com/reconstruction",
          publicKey: "RECONSTRUCTION_KEY",
          capabilities: ["reconstruction"],
        },
      ],
      splatterNodes: [
        {
          id: "splatter-1",
          endpoint: "https://hq.example.com/splatter",
          capabilities: ["gaussian-splatting"],
        },
      ],
      vlmNodes: [
        {
          id: "vlm-1",
          endpoint: "wss://hq.example.com/vlm",
          transport: "wss",
          capabilities: ["vlm-inference"],
          models: ["moondream:1.8b"],
        },
      ],
      pathfindingServices: [
        {
          id: "pathfinding-1",
          endpoint: "https://hq.example.com/pathfinding",
          capabilities: ["pathfinding"],
        },
      ],
      bootstrapNodes: [
        {
          id: "bootstrap-1",
          endpoint: "https://hq.example.com/bootstrap",
          transport: "https",
        },
      ],
      wallets: [
        {
          address: "wallet-1",
          chain: "posemesh",
          role: "operator",
          publicKey: "WALLET_KEY",
        },
      ],
      publicKeys: ["MANIFEST_KEY"],
      capabilities: ["regional-bootstrap"],
      healthCheck: "https://hq.example.com/health",
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
    assert.equal(result.reconstructionNodes.length, 1);
    assert.equal(result.splatterNodes.length, 1);
    assert.equal(result.vlmNodes.length, 1);
    assert.equal(result.pathfindingServices.length, 1);
    assert.equal(result.bootstrapNodes.length, 1);
    assert.equal(result.wallets.length, 1);
    assert.equal(result.healthCheck, "https://hq.example.com/health");
    assert.deepEqual(result.publicKeys, [
      "TXT_KEY",
      "MANIFEST_KEY",
      "WALLET_KEY",
      "MANAGER_KEY",
      "RELAY_KEY",
      "RECONSTRUCTION_KEY",
    ]);
    assert.deepEqual(result.capabilities, [
      "domain-discovery",
      "relay-discovery",
      "regional-bootstrap",
      "reconstruction",
      "gaussian-splatting",
      "vlm-inference",
      "pathfinding",
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
    assert.deepEqual(result.reconstructionNodes, []);
    assert.deepEqual(result.splatterNodes, []);
    assert.deepEqual(result.vlmNodes, []);
    assert.deepEqual(result.pathfindingServices, []);
    assert.deepEqual(result.publicKeys, ["TXT_KEY"]);
    assert.deepEqual(result.capabilities, ["relay-discovery"]);
  });
});
