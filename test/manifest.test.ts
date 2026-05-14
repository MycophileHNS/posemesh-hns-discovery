import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
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
      audience: "posemesh-client",
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
    assert.deepEqual(manifest.audience, ["posemesh-client"]);
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

  it("enforces manifest schema limits", () => {
    assert.throws(
      () =>
        parsePosemeshManifest(
          {
            version: 1,
            capabilities: ["one", "two"],
          },
          { maxCapabilities: 1 },
        ),
      /capabilities exceeds limit 1/,
    );

    assert.throws(
      () =>
        parsePosemeshManifest(
          {
            version: 1,
            sourceName: "x".repeat(16),
          },
          { maxStringBytes: 8 },
        ),
      /sourceName exceeds 8 bytes/,
    );
  });

  it("rejects algorithm-specific public keys with invalid lengths", () => {
    assert.throws(
      () =>
        parsePosemeshManifest({
          version: 1,
          publicKeys: ["02aa"],
        }),
      /Ed25519|P-256/,
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

  it("rejects additional reserved and multicast manifest addresses", async () => {
    await assert.rejects(
      () => fetchPosemeshManifest("https://192.88.99.1/posemesh.json"),
      /localhost|private|reserved/,
    );

    await assert.rejects(
      () => fetchPosemeshManifest("https://[2001:db8::1]/posemesh.json"),
      /localhost|private|reserved/,
    );

    await assert.rejects(
      () => fetchPosemeshManifest("https://[ff02::1]/posemesh.json"),
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
      publicKeys: ["aa".repeat(32)],
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
    assert.deepEqual(manifest.publicKeys, ["aa".repeat(32)]);
    assert.equal(requestOptions?.hostname, "manifest.example.test");
    assert.equal(typeof requestOptions?.lookup, "function");
    assert.ok(requestOptions);
    assert.deepEqual(readPinnedAddresses(requestOptions), [
      { address: "93.184.216.34", family: 4 },
    ]);
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

  it("allows missing Content-Type only when explicitly configured", async () => {
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
          httpsRequest: createManifestHttpsRequest(signed.body, undefined, null),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /Content-Type application\/json/,
    );

    const manifest = await fetchPosemeshManifest(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body, undefined, null),
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
      allowMissingContentType: true,
    });

    assert.equal(manifest.sourceName, "hq.posemesh");
  });

  it("enforces configured TLS SPKI pins", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const peerSpki = Buffer.from("mock-spki", "utf8");
    const expectedPin = createHash("sha256").update(peerSpki).digest("base64");
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    const manifest = await fetchPosemeshManifest(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(
        signed.body,
        undefined,
        "application/json",
        peerSpki,
      ),
      tlsPins: { "manifest.example.test": [expectedPin] },
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(manifest.sourceName, "hq.posemesh");

    await assert.rejects(
      () =>
        fetchPosemeshManifest(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(
            signed.body,
            undefined,
            "application/json",
            peerSpki,
          ),
          tlsPins: { "manifest.example.test": ["AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="] },
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /SPKI pin mismatch/,
    );
  });

  it("validates opt-in DANE TLSA records for manifest hosts", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const peerSpki = Buffer.from("mock-dane-spki", "utf8");
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(
        signed.body,
        undefined,
        "application/json",
        peerSpki,
      ),
      enableDane: true,
      resolveTlsa: async (hostname, port) => {
        assert.equal(hostname, "manifest.example.test");
        assert.equal(port, 443);

        return [
          {
            certUsage: 3,
            selector: 1,
            matchingType: 1,
            data: createHash("sha256").update(peerSpki).digest(),
          },
        ];
      },
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.dane?.status, "validated");
    assert.equal(fetched.dane?.recordName, "_443._tcp.manifest.example.test");
    assert.equal(fetched.dane?.matchedRecord?.selector, 1);
  });

  it("falls back with a warning when optional DANE has no TLSA records", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const peerSpki = Buffer.from("mock-dane-spki", "utf8");
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(
        signed.body,
        undefined,
        "application/json",
        peerSpki,
      ),
      enableDane: true,
      resolveTlsa: async () => [],
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.dane?.status, "no-records");
    assert.match(fetched.warnings?.[0]?.message ?? "", /No TLSA records/);
  });

  it("fails closed when requireTlsa is enabled and no TLSA records exist", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const peerSpki = Buffer.from("mock-dane-spki", "utf8");
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(
            signed.body,
            undefined,
            "application/json",
            peerSpki,
          ),
          securityMode: "strict",
          enableDane: true,
          requireTlsa: true,
          resolveTlsa: async () => [],
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /TLSA records are required/,
    );
  });

  it("rejects mismatched DANE TLSA records", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const peerSpki = Buffer.from("mock-dane-spki", "utf8");
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(
            signed.body,
            undefined,
            "application/json",
            peerSpki,
          ),
          enableDane: true,
          resolveTlsa: async () => [
            {
              certUsage: 3,
              selector: 1,
              matchingType: 1,
              data: createHash("sha256").update("wrong-spki").digest(),
            },
          ],
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /did not match any TLSA record/,
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

  it("does not treat plain manifests with legacy signature fields as signed envelopes", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const body = JSON.stringify({
      version: 1,
      sourceName: "hq.posemesh",
      signature: "legacy-inline-signature",
    });

    for (const securityMode of ["permissive", "demo"] as const) {
      const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
        resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
        httpsRequest: createManifestHttpsRequest(body),
        securityMode,
        expectedName: "hq.posemesh",
      });

      assert.equal(fetched.manifest.sourceName, "hq.posemesh");
      assert.equal(fetched.manifest.signature, "legacy-inline-signature");
      assert.equal(fetched.verification.status, "unsigned-allowed");
    }
  });

  it("returns cache metadata from manifest freshness policy", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
      maxManifestAgeMs: 2 * 60 * 60 * 1000,
    });

    assert.equal(fetched.cache.cacheStatus, "fresh");
    assert.equal(fetched.cache.ageMs, 60 * 60 * 1000);
    assert.equal(fetched.cache.maxManifestAgeMs, 2 * 60 * 60 * 1000);
  });

  it("rejects manifests older than maxManifestAgeMs", async () => {
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
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T03:00:00.000Z"),
          maxManifestAgeMs: 60 * 60 * 1000,
        }),
      /Manifest age/,
    );
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

  it("requires issuedAt and expiresAt in strict signed manifests", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /include issuedAt/,
    );
  });

  it("allows missing replay timestamps in demo mode with warnings", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
    });

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      securityMode: "demo",
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.manifest.sourceName, "hq.posemesh");
    assert.match(
      fetched.warnings?.map((warning) => warning.message).join("\n") ?? "",
      /without issuedAt[\s\S]*without expiresAt/,
    );
  });

  it("normalizes signed sourceName, manifestUrl, and audience bindings", async () => {
    const requestedUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      sourceName: "HQ.POSEMESH.",
      manifestUrl: "https://MANIFEST.EXAMPLE.TEST./posemesh.json",
      audience: ["Posemesh-Client."],
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    const fetched = await fetchPosemeshManifestWithVerification(requestedUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      trustedKeys: [signed.trustedKey],
      expectedName: "hq.posemesh",
      expectedAudience: "posemesh-client",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.verification.status, "verified");
  });

  it("rejects signed manifests whose name conflicts with expectedName", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh.json";
    const signed = createSignedManifestBody({
      version: 1,
      name: "evil.posemesh",
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /Manifest name evil\.posemesh does not match requested name hq\.posemesh/,
    );
  });

  it("requires configured audience in strict signed manifests", async () => {
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
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          trustedKeys: [signed.trustedKey],
          expectedName: "hq.posemesh",
          expectedAudience: "posemesh-client",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /include audience/,
    );
  });

  it("ignores verification keys outside their rotation window", async () => {
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
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(signed.body),
          trustedKeys: [
            {
              ...signed.trustedKey,
              notAfter: "2026-05-11T00:00:00.000Z",
            },
          ],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /No currently valid/,
    );

    const fetched = await fetchPosemeshManifestWithVerification(manifestUrl, {
      resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
      httpsRequest: createManifestHttpsRequest(signed.body),
      trustedKeys: [
        {
          ...signed.trustedKey,
          notBefore: "2026-05-11T00:00:00.000Z",
          notAfter: "2026-05-13T00:00:00.000Z",
        },
      ],
      expectedName: "hq.posemesh",
      now: () => new Date("2026-05-12T01:00:00.000Z"),
    });

    assert.equal(fetched.verification.keyNotBefore, "2026-05-11T00:00:00.000Z");
    assert.equal(fetched.verification.keyNotAfter, "2026-05-13T00:00:00.000Z");
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

  it("rejects RSA SPKI keys for ECDSA P-256 signed manifests", async () => {
    const manifestUrl = "https://manifest.example.test/posemesh-rsa-as-p256.json";
    const manifest: PosemeshManifest = {
      version: 1,
      sourceName: "hq.posemesh",
      manifestUrl,
      issuedAt: "2026-05-12T00:00:00.000Z",
      expiresAt: "2026-05-12T12:00:00.000Z",
    };
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const payloadBytes = Buffer.from(JSON.stringify(manifest), "utf8");
    const signature = sign("sha256", createManifestSigningBytes(payloadBytes), privateKey);
    const rsaSpki = publicKey.export({ format: "der", type: "spki" });
    const body = JSON.stringify({
      version: 1,
      payload: payloadBytes.toString("base64url"),
      signature: signature.toString("base64url"),
      algorithm: "ecdsa-p256-sha256",
      keyId: "rsa-not-p256",
    });

    await assert.rejects(
      () =>
        fetchPosemeshManifestWithVerification(manifestUrl, {
          resolveHostname: async () => [{ address: "93.184.216.34", family: 4 }],
          httpsRequest: createManifestHttpsRequest(body),
          trustedKeys: [
            {
              id: "rsa-not-p256",
              algorithm: "ecdsa-p256-sha256",
              publicKey: Buffer.from(rsaSpki).toString("base64url"),
              source: "trusted",
            },
          ],
          expectedName: "hq.posemesh",
          now: () => new Date("2026-05-12T01:00:00.000Z"),
        }),
      /Manifest signature verification failed/,
    );
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
  contentType: string | null = "application/json; charset=utf-8",
  peerCertificatePubkey?: Buffer,
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
        "content-length": String(Buffer.byteLength(body)),
      };

      if (contentType !== null) {
        response.headers["content-type"] = contentType;
      }

      if (peerCertificatePubkey) {
        Object.defineProperty(response, "socket", {
          value: {
            getPeerCertificate: () => ({
              pubkey: peerCertificatePubkey,
            }),
          },
        });
      }

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

function readPinnedAddresses(options: RequestOptions): Array<{ address: string; family: number }> {
  const lookup = options.lookup;

  if (typeof lookup !== "function") {
    throw new Error("Expected pinned lookup function.");
  }

  let pinnedAddresses: Array<{ address: string; family: number }> = [];
  lookup(String(options.hostname), { all: true }, (_error, addresses) => {
    if (!Array.isArray(addresses)) {
      throw new Error("Expected pinned lookup to return address objects for all=true.");
    }

    pinnedAddresses = addresses.map((address) => ({
      address: address.address,
      family: address.family,
    }));
  });

  return pinnedAddresses;
}
