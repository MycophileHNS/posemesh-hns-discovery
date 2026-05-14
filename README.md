# posemesh-hns-discovery

`posemesh-hns-discovery` is an unofficial proof of concept that shows how Handshake names could help Posemesh clients, tools, robots, and agents discover Auki/Posemesh services without depending on one central directory.

This is not official Auki software. It is not endorsed by Auki Labs. It is not a production Posemesh SDK fork. It is a small discussion prototype.

## Five-minute summary

Posemesh is decentralized physical-world infrastructure. To use it, software needs to find the right services: domain managers, relays, reconstruction nodes, splatter nodes, VLM nodes, pathfinding services, bootstrap nodes, wallets, and public keys.

In plain language, this prototype asks:

> Could a stable Handshake name like `hq.posemesh` or `relays.posemesh` help Posemesh clients find the right infrastructure, even when servers, keys, or regions change?

This repository demonstrates a plausible yes, at proof-of-concept level.

A Posemesh client, robot, SDK, or agent may need to answer questions like:

- Where are the relays?
- Which domain managers are available?
- Which region should I use?
- Which compute nodes can do reconstruction or splatting?
- Which public keys identify the operator?
- Which endpoint should a robot, SDK, or agent call first?

Today, answers like that can come from a console, a central API, a config file, or documentation. Those are useful, but they can also become single points of discovery. If the directory moves, an API changes, or a region is reorganized, clients need another way to find the next correct endpoint.

This prototype explores another option: publish a small machine-readable discovery record in Handshake DNS TXT records. The TXT record can point to a JSON manifest. The manifest lists Posemesh service endpoints, capabilities, wallets, keys, regions, and health checks.

The result is a stable name that can keep working even when the infrastructure behind it moves. This does not replace Posemesh APIs, the Posemesh Console, or Auki-controlled infrastructure. It gives them a resilient discovery layer.

Live lookups require a Handshake-aware DNS resolver or resolver API. The default demo uses mock records so reviewers can understand the flow without setting up Handshake infrastructure.

## Why Handshake + .posemesh matters

The proposed integration should stay focused on `.posemesh`. The intent is that `.posemesh` can become a resilient discovery root for Posemesh infrastructure if Auki chooses to accept and operate it.

Handshake matters here because it can provide an owner-controlled name that is not tied to one cloud account, one API host, or one documentation page. The name can stay stable while the records behind it point to current infrastructure.

The important idea is not "make a website resolve in a browser." These names are headless. Agents, CLIs, SDKs, robots, and services can resolve them through DNS, resolver APIs, or Handshake-aware infrastructure.

The useful idea is:

> A Handshake name can act as an owner-controlled discovery and identity anchor for Auki-operated and community-operated Posemesh infrastructure.

Handshake helps because the name can remain stable while endpoints, regions, keys, and service operators change. That makes Posemesh more resilient to API moves, cloud migrations, service reorganization, and future community-operated infrastructure.

For the Auki team, the strongest reason to consider this is resilience: clients can start from a durable name, verify the metadata they receive, and then connect to the current Posemesh services. That creates a path toward decentralized discovery without forcing a production SDK fork.

## Example .posemesh names

These examples are hypothetical. This repository does not control `.posemesh`, does not claim Auki has accepted or deployed it, and does not publish official Auki records.

- `nils.posemesh` could identify a person, operator, or trusted node group.
- `hq.posemesh` could identify Auki or Posemesh headquarters infrastructure.
- `americaNorth.posemesh` could identify regional infrastructure.
- `relays.posemesh` could publish relay discovery.
- `domains.posemesh` could publish domain manager discovery.

This repository demos `.posemesh` names such as `hq.posemesh`, `relays.posemesh`, and `americaNorth.posemesh`.

## What this prototype does

The prototype:

- resolves TXT records for subnames under `.posemesh`
- parses compact `posemesh:v1` TXT records
- parses `agent-identity:v1` TXT records
- fetches a remote manifest JSON when a TXT record points to one
- requires signed manifest envelopes for built-in live manifest fetching
- validates a small Posemesh-oriented manifest shape
- returns one normalized discovery result
- reports TXT parse warnings instead of silently hiding malformed records
- includes mock records so the demo works without live Handshake records

The normalized result can include:

- regions
- domain managers
- relays
- reconstruction nodes
- splatter nodes
- VLM nodes
- pathfinding services
- bootstrap nodes
- wallets
- public keys
- capabilities
- health check URL
- manifest URL
- agent endpoint URLs
- resolution timestamp
- parse warnings

## What this prototype proves

This prototype demonstrates the basic discovery flow in a small, reviewable repo:

1. A stable Handshake name can point to Posemesh discovery metadata.
2. The metadata can be small enough to fit in TXT records.
3. TXT records can point to richer manifest JSON.
4. The manifest can describe Posemesh service categories drawn from public Auki repositories.
5. A client can normalize all of that into one predictable object.

It also proves that this can be done as a separate layer. The prototype does not modify Posemesh, hsd, hnsd, or any Auki repository. That is important for review: the idea can be evaluated without treating this repo as an Auki SDK fork.

The practical value is resilience. A Posemesh client could discover where to go next from a name instead of depending only on a central service directory.

For a longer Auki-facing argument, see [`docs/auki-resilience-case.md`](docs/auki-resilience-case.md).

## What Auki would need to productionize

A production version would need Auki-owned decisions and engineering work beyond this prototype. The important next steps would be:

- decide whether to accept and operate `.posemesh` as an official namespace
- define a stable metadata specification and versioning policy
- decide which `.posemesh` subnames are official, curated, experimental, or community-owned
- publish live Handshake records controlled by the right operators
- sign manifests and verify signatures in clients
- define key rotation and revocation rules
- bind service operators to wallets and public keys
- define health check, cache, TTL, and failover behavior
- document resolver behavior for no records, lookup errors, parse errors, manifest fetch errors, and signature failures
- test compatibility with real Posemesh SDKs and deployed services
- complete a security review for endpoint trust, replay behavior, downgrade behavior, and operator impersonation
- decide how this complements the Posemesh Console and existing APIs

Until those decisions are made, this repository should remain an unofficial prototype for discussion.

## TXT record examples

Compact Posemesh discovery record:

```txt
posemesh:v1; manifest=https://example.com/posemesh/hq.json; alg=ed25519; keyId=hq-2026-05; publicKey=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa; notBefore=2026-05-01T00:00:00.000Z; notAfter=2026-08-01T00:00:00.000Z; capabilities=domain-discovery,relay-discovery
```

Agent identity record:

```txt
agent-identity:v1={"version":1,"endpoint":"https://example.com/agent.json","publicKey":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","capabilities":["domain-discovery","relay-discovery"]}
```

In this prototype, `manifest` points to Posemesh discovery JSON. `endpoint` in an `agent-identity:v1` record is kept as an agent endpoint, not treated as a Posemesh manifest unless the name also publishes a separate `posemesh:v1` manifest record.

The TXT `publicKey`, `alg`, `keyId`, `notBefore`, and `notAfter` fields are a prototype key anchor. In strict live mode, a fetched signed manifest must verify against a key anchored in the requested name's TXT record or a key explicitly supplied by the caller.

The example public key is a placeholder hex string. Real records should use the key format, key rotation rules, and wallet binding policy Auki chooses for production.

## Manifest shape

The manifest schema is intentionally small. It uses service category names observed in public Auki repositories so the prototype feels relevant to Posemesh, but it is not an official Auki schema:

```json
{
  "version": 1,
  "sourceName": "americaNorth.posemesh",
  "manifestUrl": "https://example.com/posemesh/america-north.json",
  "audience": ["posemesh-client"],
  "issuedAt": "2026-05-12T00:00:00.000Z",
  "expiresAt": "2026-05-13T00:00:00.000Z",
  "regions": ["north-america"],
  "domainManagers": [],
  "relays": [],
  "reconstructionNodes": [],
  "splatterNodes": [],
  "vlmNodes": [],
  "pathfindingServices": [],
  "bootstrapNodes": [],
  "wallets": [],
  "publicKeys": [],
  "capabilities": [],
  "healthCheck": "https://example.com/health"
}
```

Built-in live manifest fetching now defaults to strict signed-envelope verification. The signing key must be anchored in TXT metadata for the requested `.posemesh` name or supplied explicitly as a trusted key. Demo mode still uses local mock manifests so the project remains easy to review without live infrastructure.

## Signed Manifest Format

Signed envelopes carry the manifest JSON as a base64url payload and sign the exact payload bytes with a Posemesh-specific signing context, currently `posemesh-manifest:v1\n` followed by the raw payload bytes:

```json
{
  "version": 1,
  "payload": "BASE64URL_MANIFEST_JSON",
  "signature": "BASE64URL_SIGNATURE",
  "algorithm": "ed25519",
  "keyId": "operator-key-1"
}
```

The `payload` decodes to the manifest JSON. In strict mode that signed payload must include:

- `version: 1`
- `sourceName` matching the requested `.posemesh` name
- `manifestUrl` matching the fetched URL
- `issuedAt` and `expiresAt` as strict ISO-8601 UTC timestamps
- `audience` when the caller configures an expected audience

Supported signature algorithms in this prototype are `ed25519` and `ecdsa-p256-sha256`. Production clients still need Auki-owned signing policy, canonicalization rules, key rotation rules, revocation rules, and operational security review before trusting this format for deployed infrastructure.

For safety, the built-in manifest fetcher only follows `https:` manifest URLs, rejects redirects, checks hostnames for localhost/private/reserved addresses, pins the checked address for the request, applies a timeout, and limits response size. Those guardrails are still prototype defaults, not a full production trust model; production clients should use stronger network isolation and signed manifests because DNS answers can change over time.

## Security

Security policy and disclosure guidance live in [`SECURITY.md`](SECURITY.md). The detailed prototype threat model lives in [`docs/threat-model.md`](docs/threat-model.md).

This section summarizes the defaults and trust assumptions reviewers should understand before trying live `.posemesh` resolution. The short version: demo mode is for discussion, live mode should use strict signed manifests, anchored keys, a Handshake-aware resolver, and explicit resolver trust policy.

### DANE TLSA Usage

Handshake can publish DNS records outside the conventional ICANN root, so this prototype treats DANE TLSA as the preferred certificate-binding direction for future production work.

When `enableDane` is set, the manifest fetcher queries `_443._tcp.<manifest-host>` through the configured TLSA resolver and compares the presented TLS certificate or public key against TLSA records. DANE is only meaningful when those TLSA answers come from a trusted Handshake-aware resolver path; an untrusted resolver can lie about TLSA records just like it can lie about TXT records. To avoid overstating DANE semantics, this prototype only supports TLSA cert usage `3` (`DANE-EE`). It supports selector `0` (full certificate), selector `1` (SPKI), and matching types `0`, `1`, and `2` for that DANE-EE subset.

If DANE is enabled but no TLSA records exist, the fetcher falls back to normal TLS validation and returns a warning. If `requireTlsa` is set, missing, invalid, or mismatched TLSA records fail closed.

Real `.posemesh` usage would need a trusted Handshake-aware TLSA resolver. A normal system DNS resolver may not know about `.posemesh` or its TLSA records. Supporting other DANE usages, such as PKIX-TA or DANE-TA, would require additional validation logic and security review.

### Resolver Trust & Consensus

The resolver interface stays small:

```ts
resolveTxt(name: string): Promise<string[]>
```

For production-like review, resolvers can also return detailed status through `resolveTxtDetailed()` and `resolveTlsaDetailed()`.

Available resolver strategies:

- `MockResolver`: deterministic local demo data.
- `DnsResolver`: Node DNS resolver, optionally configured with a DNS server.
- `DohResolver`: DNS-over-HTTPS resolver using native `fetch`. Its default endpoint is Cloudflare's conventional DNS service, so live `.posemesh` lookups require configuring a Handshake-aware DoH endpoint or another Handshake-aware resolver.
- `DotResolver`: explicit DNS-over-TLS prototype stub.
- `CompositeResolver`: combines multiple resolvers with `first-success`, `quorum`, or `strict-consensus`.

`first-success` is useful for availability. `quorum` is useful when several resolvers should agree before a result is accepted. `strict-consensus` is the most conservative strategy and fails if resolver answers differ.

### Production Defaults

The safest production direction would be:

- use only `.posemesh` subnames controlled or delegated by Auki
- use `strict` security mode for live manifest fetching
- set `requireManifest: true` for callers that must fail closed instead of returning TXT-only fallback data
- require signed manifest envelopes
- anchor signing keys in TXT records or an Auki-controlled trust store
- require `sourceName`, `manifestUrl`, `issuedAt`, and `expiresAt` in signed payloads
- configure an expected `audience` for clients that know their trust context
- use a Handshake-aware resolver, preferably with multi-resolver quorum or strict consensus
- enable DANE TLSA validation and consider `requireTlsa` once Auki operates DANE-EE TLSA records
- keep parser and manifest limits enabled
- keep `Content-Type: application/json` enforcement enabled
- keep redirects, private IPs, localhost, link-local, multicast, documentation, and reserved addresses blocked
- treat custom `manifestFetcher` implementations as trusted code and return verified `FetchedPosemeshManifest` objects in strict production flows
- use redacted structured logging

The demo intentionally relaxes some of this so reviewers can run the project without live Handshake records, hosted manifests, or real Auki signing keys.

### Security Model & Threats

This prototype now has explicit security modes, structured error codes, parser limits, manifest limits, and optional logger hooks so reviewers can see how discovery fails instead of guessing from strings or silent fallbacks.

The default live manifest mode is `strict`. In strict mode, a fetched manifest must be a signed envelope, the signature must verify, the key must be anchored in TXT metadata or supplied by the caller, and the signed payload must match the requested `.posemesh` name and manifest URL. Signed manifests also require `issuedAt` and `expiresAt` so clients can reject stale or replayed metadata.

The main threats considered are TXT tampering, manifest tampering, replay, unsafe manifest URLs, resolver failure or disagreement, oversized inputs, and misleading logs. Current mitigations include HTTPS-only manifest URLs, rejection of private or reserved resolved addresses, redirect blocking, strict `application/json` responses, byte and timeout limits, optional DANE TLSA validation, optional multi-resolver strategies, and redacted structured logging.

Threat boundaries:

- TXT records can point to manifests and anchor verification keys, but TXT alone is not enough to trust live metadata.
- HTTPS protects transport to the manifest host, but strict signed payload verification is the main integrity check.
- DANE TLSA can bind certificate material to DNS records when a trusted Handshake-aware TLSA resolver is configured. This prototype intentionally limits that support to DANE-EE records.
- Resolver consensus can reduce disagreement risk, but it does not prove that records are official Auki records.
- Logs are opt-in and redacted, but production operators still need retention and privacy policies.

For the detailed threat model, see [`docs/threat-model.md`](docs/threat-model.md).

## Prototype Limitations

Demo behavior and live behavior are intentionally different.

Demo mode:

- uses mock TXT records from [`src/demo.ts`](src/demo.ts)
- does not require live `.posemesh` records
- can show unsigned manifest flows for review
- should not be treated as a trust model

Live behavior:

- requires a Handshake-aware DNS resolver for real `.posemesh` records
- defaults to strict signed manifest verification
- rejects unsigned fetched manifests unless the caller explicitly selects `demo` or `permissive`
- requires a configured TLSA resolver before DANE checks are meaningful

Prototype-only limitations:

- `.posemesh` is not claimed to be accepted or operated by Auki in this repository
- the manifest schema is not an official Auki schema
- key governance, revocation, and wallet binding are not productionized
- the core library reports cache policy metadata but does not implement a persistent cache
- DNS-over-TLS is a stub
- SPKI pinning exists as an opt-in fallback, but DANE TLSA is the preferred direction for Handshake-aware certificate binding
- CI gates and `npm audit` do not replace a production security review

## Common Failure Modes

Warnings and thrown `DiscoveryError` objects include stable `code` values. Callers should use codes instead of parsing English messages.

| Code | Meaning |
| --- | --- |
| `INVALID_POSEMESH_NAME` | The requested name is not an accepted `.posemesh` subname. |
| `TXT_NO_RECORDS` | The resolver returned no TXT records for the name. |
| `TXT_NO_COMPATIBLE_RECORDS` | TXT records exist, but none use supported `posemesh:v1` or `agent-identity:v1` formats. |
| `TXT_PARSE_ERROR` | A TXT record looked relevant but could not be parsed. |
| `TXT_LIMIT_EXCEEDED` | TXT record count, size, field, key, or capability limits were exceeded. |
| `TXT_AMBIGUOUS_MANIFEST` | Multiple distinct manifest URLs were found, so manifest fetch was skipped. |
| `RESOLVER_LOOKUP_ERROR` | A DNS, DoH, TLSA, or composite resolver lookup failed. |
| `RESOLVER_CONSENSUS_FAILED` | Composite resolver quorum or strict consensus could not agree. |
| `RESOLVER_UNSUPPORTED` | A requested resolver path is a prototype stub or lacks a needed record type. |
| `MANIFEST_URL_INVALID` | The manifest URL is malformed or not `https:`. |
| `MANIFEST_URL_UNSAFE` | The manifest host is localhost, private, link-local, multicast, documentation, reserved, or mixed public/private. |
| `MANIFEST_HTTP_ERROR` | The manifest server returned a non-2xx HTTP status. |
| `MANIFEST_REDIRECT_REJECTED` | The manifest server returned a redirect, which this prototype rejects. |
| `MANIFEST_FETCH_ERROR` | Manifest fetching failed or `requireManifest` could not accept a TXT-only fallback. |
| `MANIFEST_CONTENT_TYPE_INVALID` | The manifest response did not use `Content-Type: application/json`. |
| `MANIFEST_TOO_LARGE` | The manifest response exceeded the configured byte limit. |
| `MANIFEST_TIMEOUT` | The manifest fetch exceeded the configured timeout. |
| `MANIFEST_PARSE_ERROR` | The manifest response was not valid JSON. |
| `MANIFEST_SCHEMA_INVALID` | Manifest JSON did not match the expected prototype schema. |
| `MANIFEST_SIGNATURE_REQUIRED` | Strict mode required a signed manifest envelope. |
| `MANIFEST_SIGNATURE_INVALID` | Signature verification failed or the signed envelope was malformed. |
| `MANIFEST_KEY_REQUIRED` | No anchored or trusted verification key was available. |
| `MANIFEST_KEY_INACTIVE` | A matching key existed but was outside its rotation window. |
| `MANIFEST_REPLAY_INVALID` | `issuedAt`, `expiresAt`, TTL, age, or clock-skew checks failed. |
| `MANIFEST_BINDING_MISMATCH` | Signed manifest identity fields did not match the requested name, URL, or audience. |
| `MANIFEST_PUBLIC_KEY_INVALID` | A TXT, manifest, wallet, or service public key was malformed. |
| `MANIFEST_TLS_PIN_MISMATCH` | Optional SPKI pinning was configured and did not match the presented certificate. |
| `DANE_TLSA_LOOKUP_ERROR` | TLSA lookup or record parsing failed. |
| `DANE_TLSA_REQUIRED` | `requireTlsa` was set but no usable TLSA record was found. |
| `DANE_TLSA_MISMATCH` | Presented TLS certificate material did not match TLSA records. |

## Dependency Surface

The runtime library intentionally has no third-party runtime dependencies. It uses Node.js built-ins for DNS, HTTPS, crypto, and fetch-compatible DoH support.

Development dependencies are limited to TypeScript and Node.js type definitions. CI runs typecheck, tests, build, `npm audit`, and `npm pack --dry-run` so dependency and packaging issues are visible before sharing changes.

See [`SECURITY.md`](SECURITY.md) for disclosure guidance and known limitations.

## Run the demo

The packaged library targets Node.js 22.6+. The source-level npm scripts use Node's experimental TypeScript transform support, so use a current Node 22 release for `npm test`, `npm run demo`, and `npm run resolve`. No live DNS records are required for the default demo.

```bash
npm ci
npm run typecheck
npm run build
node dist/cli.js demo
node dist/cli.js resolve hq.posemesh
```

With a current Node 22 release, reviewers can also run the source scripts and package checks:

```bash
npm test
npm run audit:security
npm run pack:dry-run
npm run demo
npm run resolve -- hq.posemesh
npm run resolve -- nils.posemesh
npm run resolve -- americaNorth.posemesh
```

The default CLI mode uses mock records from [`src/demo.ts`](src/demo.ts).

The CLI intentionally accepts only subnames under `.posemesh`, such as `hq.posemesh` or `relays.posemesh`. The root name `posemesh` and unrelated Handshake names are outside this prototype.

`--require-manifest` is intended for live or otherwise verified manifest fetching. The default demo mode uses local unsigned mock manifests, so use `--live` with `--require-manifest` or omit the flag for mock-record walkthroughs.

To try live DNS resolution through a Handshake-aware resolver:

```bash
npm run resolve -- hq.posemesh --live --dns-server 127.0.0.1:5350
npm run resolve -- hq.posemesh --live --dns-server 127.0.0.1:5350 --require-manifest
```

That DNS server could be backed by software such as hsd or hnsd, depending on the operator's setup.

Strict live library usage should supply explicit trust anchors and resolver policy:

```ts
import {
  CompositeResolver,
  DnsResolver,
  discoverPosemesh,
  type ManifestVerificationKey,
} from "posemesh-hns-discovery";

const trustedKeys: ManifestVerificationKey[] = [
  {
    id: "hq-2026-05",
    algorithm: "ed25519",
    publicKey: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    source: "trusted",
    notBefore: "2026-05-01T00:00:00.000Z",
    notAfter: "2026-08-01T00:00:00.000Z",
  },
];

const resolver = new CompositeResolver(
  [
    new DnsResolver("127.0.0.1:5350", "hns-local-a"),
    new DnsResolver("127.0.0.1:5351", "hns-local-b"),
  ],
  { strategy: "quorum", quorum: 2 },
);

const result = await discoverPosemesh("hq.posemesh", {
  resolver,
  tlsaResolver: resolver,
  requireManifest: true,
  manifestFetchOptions: {
    securityMode: "strict",
    trustedKeys,
    expectedAudience: "posemesh-client",
    enableDane: true,
  },
});
```

This example uses `CompositeResolver` with `quorum` so resolver answers must agree. Other strategies are `first-success` for availability and `strict-consensus` for the most conservative review path. `enableDane` queries TLSA records for manifest hosts; set `requireTlsa: true` only after the relevant TLSA records are expected to exist.

If live mode returns no TXT records, first confirm the configured resolver can resolve Handshake names. A normal system DNS resolver may not know about `.posemesh`.

## Project layout

- [`src/types.ts`](src/types.ts) defines the discovery and manifest types.
- [`src/name.ts`](src/name.ts) validates `.posemesh` names for the current prototype.
- [`src/parser.ts`](src/parser.ts) parses compact Posemesh TXT records and `agent-identity:v1` records.
- [`src/resolvers.ts`](src/resolvers.ts) contains `MockResolver`, `DnsResolver`, `DohResolver`, `DotResolver`, and `CompositeResolver`.
- [`src/manifest.ts`](src/manifest.ts) fetches and validates manifest JSON, including Posemesh-oriented service categories.
- [`src/security.ts`](src/security.ts) verifies signed manifest envelopes.
- [`src/observability.ts`](src/observability.ts) defines structured errors and redacted logging helpers.
- [`src/discover.ts`](src/discover.ts) contains `discoverPosemesh(name, options)`.
- [`src/cli.ts`](src/cli.ts) powers `npm run resolve` and `npm run demo`.
- [`test/`](test) contains Node test runner coverage.
- [`examples/`](examples) contains small demo and live-DNS examples.
- [`docs/threat-model.md`](docs/threat-model.md) documents the security model and remaining production work.
- [`SECURITY.md`](SECURITY.md) documents responsible disclosure and prototype support status.

## Reviewed reference projects

- [Posemesh](https://github.com/aukilabs/posemesh)
- [Domain Server](https://github.com/aukilabs/domain-server)
- [Relay / Hagall](https://github.com/aukilabs/hagall)
- [Reconstruction Server](https://github.com/aukilabs/reconstruction-server)
- [Splatter Server](https://github.com/aukilabs/splatter-server)
- [VLM Node](https://github.com/aukilabs/vlm-node)
- [Pathfinding](https://github.com/aukilabs/pathfinding)
- [hsd](https://github.com/handshake-org/hsd)
- [hnsd](https://github.com/handshake-org/hnsd)
- [hs-client](https://github.com/handshake-org/hs-client)
- [handshake-agent-resolver](https://github.com/MycophileHNS/handshake-agent-resolver)
