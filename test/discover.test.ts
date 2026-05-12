import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { discoverPosemesh } from "../src/discover.ts";
import { MockResolver } from "../src/resolvers.ts";
import type { PosemeshManifest } from "../src/types.ts";

const fixedNow = new Date("2026-05-11T00:00:00.000Z");
const TXT_KEY = "02aa";
const MANIFEST_KEY = "02bb";
const WALLET_KEY = "02cc";
const MANAGER_KEY = "02dd";
const RELAY_KEY = "02ee";
const RECONSTRUCTION_KEY = "02ff";

describe("discoverPosemesh", () => {
  it("returns normalized discovery output from TXT and manifest data", async () => {
    const resolver = new MockResolver({
      "hq.posemesh": [
        `posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=${TXT_KEY}; capabilities=domain-discovery,relay-discovery`,
      ],
    });
    const manifest: PosemeshManifest = {
      version: 1,
      sourceName: "hq.posemesh",
      domainManagers: [
        {
          id: "manager-1",
          endpoint: "https://hq.example.com/domain-manager",
          publicKey: MANAGER_KEY,
          capabilities: ["domain-discovery"],
        },
      ],
      relays: [
        {
          id: "relay-1",
          endpoint: "wss://hq.example.com/relay",
          transport: "wss",
          publicKey: RELAY_KEY,
        },
      ],
      reconstructionNodes: [
        {
          id: "reconstruction-1",
          endpoint: "https://hq.example.com/reconstruction",
          publicKey: RECONSTRUCTION_KEY,
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
          publicKey: WALLET_KEY,
        },
      ],
      publicKeys: [MANIFEST_KEY],
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
    assert.deepEqual(result.agentEndpoints, []);
    assert.equal(result.resolvedAt, fixedNow.toISOString());
    assert.deepEqual(result.warnings, []);
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
      TXT_KEY,
      MANIFEST_KEY,
      WALLET_KEY,
      MANAGER_KEY,
      RELAY_KEY,
      RECONSTRUCTION_KEY,
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
          `posemesh:v1; manifest=https://example.com/relays.json; publicKey=${TXT_KEY}; capabilities=relay-discovery`,
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
    assert.deepEqual(result.publicKeys, [TXT_KEY]);
    assert.deepEqual(result.capabilities, ["relay-discovery"]);
    assert.deepEqual(result.warnings, []);
  });

  it("passes manifest fetch options to the configured fetcher", async () => {
    const manifest: PosemeshManifest = {
      version: 1,
      sourceName: "hq.posemesh",
    };
    const manifestFetchOptions = { timeoutMs: 1_000, maxBytes: 4_096 };
    let receivedOptions: unknown;

    await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": ["posemesh:v1; manifest=https://example.com/hq.json"],
      }),
      manifestFetchOptions,
      manifestFetcher: async (_url, options) => {
        receivedOptions = options;
        return manifest;
      },
      now: () => fixedNow,
    });

    assert.deepEqual(receivedOptions, {
      ...manifestFetchOptions,
      trustedKeys: [],
      expectedName: "hq.posemesh",
      expectedManifestUrl: "https://example.com/hq.json",
    });
  });

  it("anchors manifest verification keys from posemesh TXT records", async () => {
    const txtPublicKey = Buffer.alloc(32, 1).toString("base64");
    let receivedOptions: unknown;

    await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": [
          `posemesh:v1; manifest=https://example.com/hq.json; alg=ed25519; keyId=hq-key; publicKey=${txtPublicKey}`,
        ],
      }),
      manifestFetcher: async (_url, options) => {
        receivedOptions = options;
        return {
          version: 1,
          sourceName: "hq.posemesh",
        };
      },
      now: () => fixedNow,
    });

    assert.deepEqual(receivedOptions, {
      trustedKeys: [
        {
          id: "hq-key",
          algorithm: "ed25519",
          publicKey: txtPublicKey,
          source: "txt",
        },
      ],
      expectedName: "hq.posemesh",
      expectedManifestUrl: "https://example.com/hq.json",
    });
  });

  it("surfaces TXT parse warnings in the normalized result", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": [
          "posemesh:v1; broken",
          `posemesh:v1; publicKey=${TXT_KEY}`,
        ],
      }),
      fetchManifest: false,
      now: () => fixedNow,
    });

    assert.deepEqual(result.publicKeys, [TXT_KEY]);
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0]?.record, "posemesh:v1; broken");
  });

  it("keeps TXT-derived data when manifest fetching fails", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": [
          `posemesh:v1; manifest=https://example.com/missing.json; publicKey=${TXT_KEY}; capabilities=domain-discovery`,
        ],
      }),
      manifestFetcher: async () => {
        throw new Error("demo fetch failed");
      },
      now: () => fixedNow,
    });

    assert.equal(result.manifestUrl, "https://example.com/missing.json");
    assert.deepEqual(result.publicKeys, [TXT_KEY]);
    assert.deepEqual(result.capabilities, ["domain-discovery"]);
    assert.equal(result.warnings.length, 1);
    assert.equal(result.warnings[0]?.source, "manifest");
    assert.equal(result.warnings[0]?.url, "https://example.com/missing.json");
  });

  it("surfaces demo-mode unsigned manifest warnings in normalized discovery", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": ["posemesh:v1; manifest=https://manifest.example.test/posemesh.json"],
      }),
      manifestFetchOptions: {
        securityMode: "demo",
        resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
        httpsRequest: createManifestHttpsRequest(
          JSON.stringify({
            version: 1,
            sourceName: "hq.posemesh",
          }),
        ),
      },
      now: () => fixedNow,
    });

    assert.equal(result.sourceName, "hq.posemesh");
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /demo mode accepted an unsigned manifest/);
  });

  it("warns when no TXT records are found", async () => {
    const result = await discoverPosemesh("missing.posemesh", {
      resolver: new MockResolver({}),
      now: () => fixedNow,
    });

    assert.deepEqual(result.publicKeys, []);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /No TXT records/);
  });

  it("does not fetch an ambiguous manifest when multiple TXT records disagree", async () => {
    let fetchCalls = 0;

    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": [
          "posemesh:v1; manifest=https://example.com/one.json",
          "posemesh:v1; manifest=https://example.com/two.json",
        ],
      }),
      manifestFetcher: async () => {
        fetchCalls += 1;
        return { version: 1 };
      },
      now: () => fixedNow,
    });

    assert.equal(fetchCalls, 0);
    assert.equal(result.manifestUrl, undefined);
    assert.match(result.warnings[0]?.message ?? "", /Multiple distinct manifest URLs/);
  });

  it("keeps agent identity endpoints separate from manifest URLs", async () => {
    let fetchCalls = 0;

    const result = await discoverPosemesh("nils.posemesh", {
      resolver: new MockResolver({
        "nils.posemesh": [
          `agent-identity:v1={"version":1,"endpoint":"https://example.com/agent.json","publicKey":"${TXT_KEY}","capabilities":["personal-agent"]}`,
        ],
      }),
      manifestFetcher: async () => {
        fetchCalls += 1;
        return { version: 1 };
      },
      now: () => fixedNow,
    });

    assert.equal(fetchCalls, 0);
    assert.equal(result.manifestUrl, undefined);
    assert.deepEqual(result.agentEndpoints, ["https://example.com/agent.json"]);
    assert.deepEqual(result.publicKeys, [TXT_KEY]);
    assert.deepEqual(result.capabilities, ["personal-agent"]);
  });

  it("drops fetched manifest data when sourceName does not match the requested name", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": ["posemesh:v1; manifest=https://example.com/hq.json"],
      }),
      manifestFetcher: async () => ({
        version: 1,
        sourceName: "mismatch.posemesh",
        relays: [{ endpoint: "wss://relay.example.com" }],
      }),
      now: () => fixedNow,
    });

    assert.equal(result.sourceName, "hq.posemesh");
    assert.deepEqual(result.relays, []);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /does not match/);
  });

  it("drops fetched manifest data when sourceName is missing", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": ["posemesh:v1; manifest=https://example.com/hq.json"],
      }),
      manifestFetcher: async () => ({
        version: 1,
        name: "hq.posemesh",
        relays: [{ endpoint: "wss://relay.example.com" }],
      }),
      now: () => fixedNow,
    });

    assert.equal(result.sourceName, "hq.posemesh");
    assert.deepEqual(result.relays, []);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /sourceName is required/);
  });

  it("drops fetched manifest data when name conflicts with the requested name", async () => {
    const result = await discoverPosemesh("hq.posemesh", {
      resolver: new MockResolver({
        "hq.posemesh": ["posemesh:v1; manifest=https://example.com/hq.json"],
      }),
      manifestFetcher: async () => ({
        version: 1,
        sourceName: "hq.posemesh",
        name: "mismatch.posemesh",
        relays: [{ endpoint: "wss://relay.example.com" }],
      }),
      now: () => fixedNow,
    });

    assert.equal(result.sourceName, "hq.posemesh");
    assert.deepEqual(result.relays, []);
    assert.equal(result.warnings.length, 1);
    assert.match(result.warnings[0]?.message ?? "", /Manifest name/);
  });
});

function createManifestHttpsRequest(body: string) {
  return ((_: RequestOptions, callback?: (response: IncomingMessage) => void) => {
    const req = new EventEmitter() as ClientRequest;

    (req as ClientRequest & { setTimeout: ClientRequest["setTimeout"] }).setTimeout = () => req;
    (req as ClientRequest & { destroy: ClientRequest["destroy"] }).destroy = (error?: Error) => {
      if (error) {
        req.emit("error", error);
      }

      return req;
    };
    (req as ClientRequest & { end: ClientRequest["end"] }).end = () => {
      const response = new PassThrough() as PassThrough & Partial<IncomingMessage>;
      response.statusCode = 200;
      response.headers = {
        "content-type": "application/json",
        "content-length": String(Buffer.byteLength(body)),
      };

      callback?.(response as IncomingMessage);
      response.end(body);
      return req;
    };

    return req;
  }) as NonNullable<import("../src/types.ts").FetchPosemeshManifestOptions["httpsRequest"]>;
}
