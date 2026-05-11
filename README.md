# posemesh-hns-discovery

`posemesh-hns-discovery` is a small open-source proof of concept for discussing how a Handshake name such as `.posemesh` could act as a decentralized discovery and identity layer for Posemesh.

This is not official Auki software. It is not a production Posemesh SDK fork. It is a standalone prototype for conversation, testing, and architecture exploration.

## What This Does

The prototype resolves TXT records for names under `.posemesh`, parses Posemesh discovery metadata, optionally fetches a remote manifest JSON file, and returns one normalized object with the services a client or agent might need:

- domain managers
- relays
- bootstrap nodes
- public keys
- capabilities
- manifest URL
- resolution timestamp

The demo works without live `.posemesh` records. By default, the CLI uses mock records for names such as `hq.posemesh`, `nils.posemesh`, and `americaNorth.posemesh`.

## Why Handshake + .posemesh Matters

Posemesh is described by Auki Labs as a decentralized machine perception network and collaborative spatial computing protocol. A discovery layer for such a network needs names that can be controlled by their owners, resolved by tools, and read by agents without depending on one application server.

Handshake can provide the naming layer. A `.posemesh` name could publish machine-readable TXT records that point to current Posemesh discovery data. That lets a name act as a stable identity anchor while the actual service endpoints, relays, bootstrap nodes, or public keys can evolve over time.

For example:

- `hq.posemesh` could identify a public headquarters or canonical directory.
- `nils.posemesh` could identify a person, maintainer, agent, or test operator.
- `americaNorth.posemesh` could identify regional relays and bootstrap nodes.
- `relays.posemesh` could publish a relay directory.
- `domains.posemesh` could publish domain manager discovery data.

These names are headless. Agents and command-line tools can resolve and use them through DNS, resolver APIs, or Handshake-aware infrastructure. Browser user experience is a separate concern, not a limitation of the names themselves.

## Supported TXT Records

Compact Posemesh discovery record:

```txt
posemesh:v1; manifest=https://example.com/posemesh.json; publicKey=BASE64_OR_HEX; capabilities=domain-discovery,relay-discovery
```

Agent identity record:

```txt
agent-identity:v1={"version":1,"endpoint":"https://example.com/agent.json","capabilities":["domain-discovery","relay-discovery"]}
```

In this prototype, `manifest` and `endpoint` both point to a JSON manifest that can add structured domain managers, relays, bootstrap nodes, public keys, and capabilities.

## Normalized Result

The main library function returns:

```ts
{
  name: string;
  sourceName: string;
  domainManagers: DomainManager[];
  relays: Relay[];
  bootstrapNodes: BootstrapNode[];
  publicKeys: string[];
  capabilities: string[];
  manifestUrl?: string;
  resolvedAt: string;
}
```

## Run The Demo

This project can run on recent Node.js versions that support built-in TypeScript transforms. No live DNS records are required for the default demo.

```bash
npm test
npm run demo
npm run resolve -- hq.posemesh
npm run resolve -- nils.posemesh
npm run resolve -- americaNorth.posemesh
```

The default CLI mode uses mock records from `src/demo.ts`.

To try live DNS resolution through a Handshake-aware resolver:

```bash
npm run resolve -- hq.posemesh --live --dns-server 127.0.0.1:5350
```

That DNS server could be backed by software such as hsd or hnsd, depending on the operator's setup.

## Project Layout

- `src/types.ts` defines the discovery and manifest types.
- `src/name.ts` validates `.posemesh` names.
- `src/parser.ts` parses compact Posemesh TXT records and `agent-identity:v1` records.
- `src/resolvers.ts` contains the resolver interface, `MockResolver`, and `DnsResolver`.
- `src/manifest.ts` fetches and validates manifest JSON.
- `src/discover.ts` contains `discoverPosemesh(name, options)`.
- `src/cli.ts` powers `npm run resolve` and `npm run demo`.
- `test/` contains Node test runner coverage.
- `examples/` contains small demo and live-DNS examples.

## What This Prototype Proves

This repository shows that a `.posemesh` name can be treated as a discovery pointer:

1. Resolve the name's TXT records.
2. Parse a compact discovery or agent identity record.
3. Fetch a manifest if the record points to one.
4. Normalize the result into one predictable object.

That is enough to demonstrate a possible decentralized discovery flow without modifying the Posemesh SDK and without forking Handshake resolver software.

## What Auki Would Need To Productionize

A production version would need decisions and engineering beyond this prototype:

- a real metadata specification and versioning policy
- live `.posemesh` records controlled by the appropriate operators
- manifest signature verification
- key rotation and revocation rules
- resolver availability and caching strategy
- security review for endpoint trust, replay behavior, and downgrade behavior
- compatibility tests against actual Posemesh services
- official ownership, maintenance, and documentation

## Prototype-Only Notes

- Manifest signature verification is marked as TODO.
- Demo URLs use `example.com` and mock data.
- The CLI defaults to mock mode so anyone can run it before live records exist.
- This project is intentionally separate from Posemesh and Handshake reference implementations.
- This repository does not claim endorsement by Auki Labs or the Handshake project.

## Reviewed Reference Projects

- [Posemesh](https://github.com/aukilabs/posemesh)
- [hsd](https://github.com/handshake-org/hsd)
- [hnsd](https://github.com/handshake-org/hnsd)
- [hs-client](https://github.com/handshake-org/hs-client)
- [handshake-agent-resolver](https://github.com/MycophileHNS/handshake-agent-resolver)
