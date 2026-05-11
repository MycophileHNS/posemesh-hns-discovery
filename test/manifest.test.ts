import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parsePosemeshManifest } from "../src/manifest.ts";

describe("Posemesh manifest parsing", () => {
  it("parses Auki-shaped node categories", () => {
    const manifest = parsePosemeshManifest({
      version: 1,
      sourceName: "americaNorth.posemesh",
      regions: ["north-america"],
      domainManagers: [
        {
          id: "domain-manager",
          endpoint: "https://domains.example.com",
          wallet: "wallet-1",
          capabilities: ["domain-discovery"],
        },
      ],
      relays: [
        {
          id: "relay",
          endpoint: "wss://relay.example.com",
          transport: "wss",
          sessionPolicy: "public",
          capabilities: ["relay-discovery"],
        },
      ],
      reconstructionNodes: [
        {
          id: "reconstruction",
          endpoint: "https://reconstruction.example.com",
          capabilities: ["reconstruction"],
        },
      ],
      splatterNodes: [
        {
          id: "splatter",
          endpoint: "https://splatter.example.com",
          capabilities: ["gaussian-splatting"],
        },
      ],
      vlmNodes: [
        {
          id: "vlm",
          endpoint: "wss://vlm.example.com/api/v1/ws",
          transport: "wss",
          models: ["moondream:1.8b"],
          capabilities: ["vlm-inference"],
        },
      ],
      pathfindingServices: [
        {
          id: "pathfinding",
          endpoint: "https://pathfinding.example.com",
          capabilities: ["pathfinding"],
        },
      ],
      bootstrapNodes: [
        {
          id: "bootstrap",
          endpoint: "https://bootstrap.example.com",
        },
      ],
      wallets: [
        {
          address: "wallet-1",
          chain: "posemesh",
          role: "operator",
        },
      ],
      healthCheck: "https://example.com/health",
    });

    assert.deepEqual(manifest.regions, ["north-america"]);
    assert.equal(manifest.domainManagers?.[0]?.wallet, "wallet-1");
    assert.equal(manifest.relays?.[0]?.sessionPolicy, "public");
    assert.equal(manifest.reconstructionNodes?.[0]?.id, "reconstruction");
    assert.equal(manifest.splatterNodes?.[0]?.id, "splatter");
    assert.deepEqual(manifest.vlmNodes?.[0]?.models, ["moondream:1.8b"]);
    assert.equal(manifest.pathfindingServices?.[0]?.id, "pathfinding");
    assert.equal(manifest.bootstrapNodes?.[0]?.id, "bootstrap");
    assert.equal(manifest.wallets?.[0]?.address, "wallet-1");
    assert.equal(manifest.healthCheck, "https://example.com/health");
  });

  it("rejects malformed Auki-shaped service arrays", () => {
    assert.throws(
      () => parsePosemeshManifest({
        version: 1,
        reconstructionNodes: [{ id: "missing-endpoint" }],
      }),
      /reconstructionNodes\.endpoint/,
    );
  });
});
