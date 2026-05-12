import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import { fetchPosemeshManifest, parsePosemeshManifest } from "../src/manifest.ts";
import type { FetchPosemeshManifestOptions } from "../src/types.ts";

describe("Posemesh manifest parsing", () => {
  it("parses Posemesh-oriented node categories", () => {
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

  it("rejects malformed Posemesh-oriented service arrays", () => {
    assert.throws(
      () => parsePosemeshManifest({
        version: 1,
        reconstructionNodes: [{ id: "missing-endpoint" }],
      }),
      /reconstructionNodes\.endpoint/,
    );
  });

  it("rejects non-string list items instead of dropping them", () => {
    assert.throws(
      () => parsePosemeshManifest({
        version: 1,
        capabilities: ["relay-discovery", 123],
      }),
      /string list item 1/,
    );
  });

  it("rejects malformed public keys", () => {
    assert.throws(
      () =>
        parsePosemeshManifest({
          version: 1,
          publicKeys: ["not_a_hex_or_base64_key"],
        }),
      /hex or base64/,
    );
  });

  it("rejects insecure manifest and service URLs", async () => {
    await assert.rejects(
      () => fetchPosemeshManifest("http://example.com/posemesh.json"),
      /https/,
    );

    await assert.rejects(
      () => fetchPosemeshManifest("https://127.0.0.1/posemesh.json"),
      /localhost|private|reserved/,
    );

    assert.throws(
      () => parsePosemeshManifest({
        version: 1,
        relays: [{ endpoint: "http://relay.example.com" }],
      }),
      /relays\.endpoint/,
    );
  });

  it("rejects manifest hostnames that resolve to private addresses", async () => {
    await assert.rejects(
      () =>
        fetchPosemeshManifest("https://manifest.example.test/posemesh.json", {
          resolveHostname: async () => [{ address: "10.0.0.5", family: 4 }],
        }),
      /resolves.*private|reserved/,
    );
  });

  it("rejects private IPv4 addresses encoded as IPv4-mapped IPv6 literals", async () => {
    await assert.rejects(
      () => fetchPosemeshManifest("https://[::ffff:127.0.0.1]/posemesh.json"),
      /localhost|private|reserved/,
    );

    await assert.rejects(
      () => fetchPosemeshManifest("https://[::ffff:7f00:1]/posemesh.json"),
      /localhost|private|reserved/,
    );

    await assert.rejects(
      () => fetchPosemeshManifest("https://[::ffff:a00:1]/posemesh.json"),
      /localhost|private|reserved/,
    );
  });

  it("fetches manifest JSON through the pinned HTTPS request path", async () => {
    const body = JSON.stringify({
      version: 1,
      sourceName: "hq.posemesh",
      publicKeys: ["02aa"],
    });
    let requestOptions: RequestOptions | undefined;

    const httpsRequest: NonNullable<FetchPosemeshManifestOptions["httpsRequest"]> = ((
      options: RequestOptions,
      callback?: (response: IncomingMessage) => void,
    ) => {
      requestOptions = options;
      const req = new EventEmitter() as ClientRequest;

      (req as ClientRequest & { setTimeout: ClientRequest["setTimeout"] }).setTimeout = () => req;
      (req as ClientRequest & { destroy: ClientRequest["destroy"] }).destroy = (
        error?: Error,
      ) => {
        if (error) {
          req.emit("error", error);
        }

        return req;
      };
      (req as ClientRequest & { end: ClientRequest["end"] }).end = () => {
        const response = new PassThrough() as PassThrough & Partial<IncomingMessage>;
        response.statusCode = 200;
        response.headers = {
          "content-length": String(Buffer.byteLength(body)),
        };

        callback?.(response as IncomingMessage);
        response.end(body);
        return req;
      };

      return req;
    }) as NonNullable<FetchPosemeshManifestOptions["httpsRequest"]>;

    const manifest = await fetchPosemeshManifest("https://manifest.example.test/posemesh.json", {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest,
    });

    assert.equal(manifest.sourceName, "hq.posemesh");
    assert.deepEqual(manifest.publicKeys, ["02aa"]);
    assert.equal(requestOptions?.hostname, "manifest.example.test");
    assert.equal(typeof requestOptions?.lookup, "function");
  });
});
