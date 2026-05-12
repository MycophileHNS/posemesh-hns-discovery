import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { EventEmitter } from "node:events";
import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";
import { PassThrough } from "node:stream";
import { describe, it } from "node:test";
import {
  fetchPosemeshManifest,
  fetchPosemeshManifestWithVerification,
  parsePosemeshManifest,
} from "../src/manifest.ts";
import { createManifestSigningBytes } from "../src/security.ts";
import type {
  FetchPosemeshManifestOptions,
  ManifestVerificationKey,
  PosemeshManifest,
} from "../src/types.ts";

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

  it("rejects hostnames when any resolved address is private", async () => {
    await assert.rejects(
      () =>
        fetchPosemeshManifest("https://manifest.example.test/posemesh.json", {
          resolveHostname: async () => [
            { address: "93.184.216.34", family: 4 },
            { address: "10.0.0.5", family: 4 },
          ],
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
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
      publicKeys: ["02aa"],
    });
    const body = signed.body;
    let requestOptions: RequestOptions | undefined;
    const httpsRequest = createManifestHttpsRequest(body, (options) => {
      requestOptions = options;
    });

    const manifest = await fetchPosemeshManifest(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest,
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(manifest.sourceName, "hq.posemesh");
    assert.deepEqual(manifest.publicKeys, ["02aa"]);
    assert.equal(requestOptions?.hostname, "manifest.example.test");
    assert.equal(typeof requestOptions?.lookup, "function");
  });

  it("tries all resolved manifest addresses until one succeeds", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });
    const attemptedAddresses: string[] = [];

    const manifest = await fetchPosemeshManifest(manifestUrl, {
      resolveHostname: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "93.184.216.35", family: 4 },
      ],
      httpsRequest: createManifestHttpsRequest(signed.body, (options) => {
        attemptedAddresses.push(readPinnedAddress(options));
        if (attemptedAddresses.length === 1) {
          throw new Error("first address failed");
        }
      }),
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(manifest.sourceName, "hq.posemesh");
    assert.deepEqual(attemptedAddresses, ["93.184.216.34", "93.184.216.35"]);
  });

  it("rejects fetched manifests without application/json content type", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifest(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body, undefined, "text/plain"),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /Content-Type application\/json/,
    );
  });

  it("rejects unsigned fetched manifests in strict mode", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifest(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(JSON.stringify(signed.manifest)),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /manifest envelope|signature/i,
    );
  });

  it("allows unsigned fetched manifests in permissive mode with a warning", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(
        JSON.stringify({
          version: 1,
          sourceName: "hq.posemesh",
        }),
      ),
      securityMode: "permissive",
      expectedName: "hq.posemesh",
    });

    assert.equal(fetched.manifest.sourceName, "hq.posemesh");
    assert.equal(fetched.verification.status, "unsigned-allowed");
    assert.match(fetched.warnings?.[0]?.message ?? "", /unsigned manifest/);
  });

  it("rejects invalid signed envelopes in permissive mode", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });
    const wrongKey = createSignedManifestBody(signed.manifest).trustedKey;

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          securityMode: "permissive",
          trustedKeys: [wrongKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /Permissive manifest verification failed/,
    );
  });

  it("allows invalid signed envelopes in demo mode with a warning", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });
    const wrongKey = createSignedManifestBody(signed.manifest).trustedKey;

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      securityMode: "demo",
      trustedKeys: [wrongKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.manifest.sourceName, "hq.posemesh");
    assert.equal(fetched.verification.status, "invalid-allowed");
    assert.match(fetched.warnings?.[0]?.message ?? "", /demo mode accepted/);
  });

  it("verifies ECDSA P-256 signed manifests", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh-p256.json";
    const signed = createSignedManifestBody(
      {
        version: 1,
        sourceName: "hq.posemesh",
        manifestUrl,
        issuedAt: "2026-05-12T00:00:00.000Z",
        expiresAt: "2026-05-12T12:00:00.000Z",
      },
      "ecdsa-p256-sha256",
    );

    const manifest = await fetchPosemeshManifest(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(manifest.sourceName, "hq.posemesh");
  });
});

function createSignedManifestBody(
  manifest: PosemeshManifest,
  algorithm: "ed25519" | "ecdsa-p256-sha256" = "ed25519",
): {
  body: string;
  manifest: PosemeshManifest;
  trustedKey: ManifestVerificationKey;
} {
  const { privateKey, publicKey } =
    algorithm === "ed25519"
      ? generateKeyPairSync("ed25519")
      : generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = publicKey.export({ format: "der", type: "spki" });
  const publicKeyBytes =
    algorithm === "ed25519" ? Buffer.from(spki).subarray(-32) : Buffer.from(spki);
  const payloadBytes = Buffer.from(JSON.stringify(manifest), "utf8");
  const signature = sign(
    algorithm === "ed25519" ? null : "sha256",
    createManifestSigningBytes(payloadBytes),
    privateKey,
  );
  const keyId = `test-${algorithm}`;

  return {
    manifest,
    body: JSON.stringify({
      version: 1,
      payload: payloadBytes.toString("base64url"),
      signature: signature.toString("base64url"),
      algorithm,
      keyId,
    }),
    trustedKey: {
      id: keyId,
      algorithm,
      publicKey: publicKeyBytes.toString("base64url"),
      source: "trusted",
    },
  };
}

function createManifestHttpsRequest(
  body: string,
  onRequest?: (options: RequestOptions) => void,
  contentType = "application/json; charset=utf-8",
): NonNullable<FetchPosemeshManifestOptions["httpsRequest"]> {
  return ((options: RequestOptions, callback?: (response: IncomingMessage) => void) => {
    const req = new EventEmitter() as ClientRequest;

    (req as ClientRequest & { setTimeout: ClientRequest["setTimeout"] }).setTimeout = () => req;
    (req as ClientRequest & { destroy: ClientRequest["destroy"] }).destroy = (error?: Error) => {
      if (error) {
        req.emit("error", error);
      }

      return req;
    };
    (req as ClientRequest & { end: ClientRequest["end"] }).end = () => {
      try {
        onRequest?.(options);
      } catch (error) {
        req.emit("error", error);
        return req;
      }

      const response = new PassThrough() as PassThrough & Partial<IncomingMessage>;
      response.statusCode = 200;
      response.headers = {
        "content-type": contentType,
        "content-length": String(Buffer.byteLength(body)),
      };

      callback?.(response as IncomingMessage);
      response.end(body);
      return req;
    };

    return req;
  }) as NonNullable<FetchPosemeshManifestOptions["httpsRequest"]>;
}

function readPinnedAddress(options: RequestOptions): string {
  const lookup = options.lookup;

  if (typeof lookup !== "function") {
    throw new Error("Expected pinned lookup function.");
  }

  let pinnedAddress = "";
  lookup(String(options.hostname), {}, (_error, address) => {
    pinnedAddress = String(address);
  });

  return pinnedAddress;
}
