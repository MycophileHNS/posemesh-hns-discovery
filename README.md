# posemesh-hns-discovery

`posemesh-hns-discovery` is an unofficial proof of concept that shows how Handshake names could help Posemesh clients, tools, robots, and agents discover Auki/Posemesh services without depending on one central directory.

This is not official Auki software. It is not endorsed by Auki Labs. It is not a production Posemesh SDK fork. It is a small discussion prototype.

## Five-minute summary

Posemesh is decentralized physical-world infrastructure. It includes domain servers, relays, reconstruction nodes, splatter nodes, VLM nodes, pathfinding services, bootstrap nodes, wallets, and public keys.

Software that wants to use Posemesh needs a way to answer simple questions:

- Where are the relays?
- Which domain managers are available?
- Which region should I use?
- Which compute nodes can do reconstruction or splatting?
- Which public keys identify the operator?
- Which endpoint should a robot, SDK, or agent call first?

Today, answers like that can come from a console, a central API, a config file, or documentation. Those are useful, but they can also become single points of discovery.

This prototype explores another option: publish a small machine-readable discovery record in Handshake DNS TXT records. That TXT record can point to a JSON manifest. The manifest lists Posemesh service endpoints, capabilities, wallets, keys, regions, and health checks.

The result is a stable name that can keep working even when the infrastructure behind it moves.

Live lookups require a Handshake-aware DNS resolver or resolver API. The default demo uses mock records so reviewers can understand the flow without setting up Handshake infrastructure.

## Why Handshake + .posemesh matters for Posemesh

The proposed integration should stay focused on `.posemesh`. The intent is that `.posemesh` can become a resilient discovery root for Posemesh infrastructure if Auki chooses to accept and operate it.

The important idea is not “make a website resolve in a browser.” These names are headless. Agents, CLIs, SDKs, robots, and services can resolve them through DNS, resolver APIs, or Handshake-aware infrastructure.

The useful idea is:

> A Handshake name can act as an owner-controlled discovery and identity anchor for Auki-operated and community-operated Posemesh infrastructure.

These are hypothetical examples only. This repository does not control `.posemesh`, does not claim Auki has accepted or deployed it, and does not publish official Auki records. If `.posemesh` were gifted to and accepted by Auki, it could publish discovery records such as:

- `hq.posemesh`: canonical Posemesh discovery manifest
- `relays.posemesh`: Relay/Hagall discovery
- `domains.posemesh`: domain manager discovery
- `americaNorth.posemesh`: regional services and bootstrap nodes
- `compute.posemesh`: reconstruction, splatter, VLM, and pathfinding services

This repository demos `.posemesh` names such as `hq.posemesh`, `relays.posemesh`, and `americaNorth.posemesh`.

Handshake helps because the name can remain stable while endpoints, regions, keys, and service operators change. That makes Posemesh more resilient to API moves, cloud migrations, service reorganization, and future community-operated infrastructure.

## What this prototype does

The prototype:

- resolves TXT records for a Posemesh-related Handshake name
- parses compact `posemesh:v1` TXT records
- parses `agent-identity:v1` TXT records
- fetches a remote manifest JSON when a TXT record points to one
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
- resolution timestamp
- parse warnings

## What this prototype proves

This prototype proves the basic discovery flow:

1. A stable Handshake name can point to Posemesh discovery metadata.
2. The metadata can be small enough to fit in TXT records.
3. TXT records can point to richer manifest JSON.
4. The manifest can describe Posemesh service categories drawn from public Auki repositories.
5. A client can normalize all of that into one predictable object.

It also proves that this can be done as a separate layer. The prototype does not modify Posemesh, hsd, hnsd, or any Auki repository.

The practical value is resilience. A Posemesh client could discover where to go next from a name instead of depending only on a central service directory.

For a longer Auki-facing argument, see [`docs/auki-resilience-case.md`](docs/auki-resilience-case.md).

## What Auki would need to productionize

A production version would need Auki-owned decisions and engineering work beyond this prototype:

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
posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=BASE64_OR_HEX; capabilities=domain-discovery,relay-discovery
```

Agent identity record:

```txt
agent-identity:v1={"version":1,"endpoint":"https://example.com/agent.json","capabilities":["domain-discovery","relay-discovery"]}
```

In this prototype, `manifest` and `endpoint` both point to a JSON manifest that can add structured service data.

## Manifest shape

The manifest schema is intentionally small. It uses service category names observed in public Auki repositories so the prototype feels relevant to Posemesh, but it is not an official Auki schema:

```json
{
  "version": 1,
  "sourceName": "americaNorth.posemesh",
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
  "healthCheck": "https://example.com/health",
  "signature": "TODO"
}
```

Signature verification is intentionally marked as prototype-only work. Production clients should not trust remote manifests without a clear signing and verification policy.

For safety, the built-in manifest fetcher only follows `https:` manifest URLs, rejects redirects, checks hostnames for localhost/private/reserved addresses before fetching, applies a timeout, and limits response size. Those guardrails are still prototype defaults, not a full production trust model; production clients should use stronger network isolation and signed manifests because DNS answers can change over time.

## Run the demo

This project can run on recent Node.js versions that support built-in TypeScript transforms. No live DNS records are required for the default demo.

```bash
npm test
npm run build
npm run demo
npm run resolve -- hq.posemesh
npm run resolve -- nils.posemesh
npm run resolve -- americaNorth.posemesh
```

The default CLI mode uses mock records from [`src/demo.ts`](src/demo.ts).

The CLI intentionally accepts only subnames under `.posemesh`, such as `hq.posemesh` or `relays.posemesh`. The root name `posemesh` and unrelated Handshake names are outside this prototype.

To try live DNS resolution through a Handshake-aware resolver:

```bash
npm run resolve -- hq.posemesh --live --dns-server 127.0.0.1:5350
```

That DNS server could be backed by software such as hsd or hnsd, depending on the operator's setup.

## Project layout

- [`src/types.ts`](src/types.ts) defines the discovery and manifest types.
- [`src/name.ts`](src/name.ts) validates `.posemesh` names for the current prototype.
- [`src/parser.ts`](src/parser.ts) parses compact Posemesh TXT records and `agent-identity:v1` records.
- [`src/resolvers.ts`](src/resolvers.ts) contains the resolver interface, `MockResolver`, and `DnsResolver`.
- [`src/manifest.ts`](src/manifest.ts) fetches and validates manifest JSON, including Posemesh-oriented service categories.
- [`src/discover.ts`](src/discover.ts) contains `discoverPosemesh(name, options)`.
- [`src/cli.ts`](src/cli.ts) powers `npm run resolve` and `npm run demo`.
- [`test/`](test) contains Node test runner coverage.
- [`examples/`](examples) contains small demo and live-DNS examples.

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
