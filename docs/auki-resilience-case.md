# Why This Could Help Auki

Status: draft proposal for discussion. This is not official Auki software, not an Auki roadmap commitment, and not a production Posemesh SDK fork.

## Short Version

The strongest reason to explore Handshake integration is resilience.

Posemesh is already presented as decentralized, civilization-scale infrastructure for machine perception, robotics, spatial computing, and the real world web. A network like that needs a discovery layer that can outlive any one service directory, cloud account, console endpoint, repository, or deployment.

Handshake can provide an owner-controlled naming layer for that discovery problem. A `.posemesh` name can act as a stable identity and discovery anchor while the service endpoints behind it change over time.

This prototype now shows one concrete path:

1. Resolve TXT records for a `.posemesh` name.
2. Parse versioned Posemesh or agent identity metadata.
3. Fetch a signed or signable manifest.
4. Return normalized service discovery data for clients, tools, robots, and agents.

The manifest schema has been expanded beyond generic relays and domain managers to include Auki-shaped categories: reconstruction nodes, splatter nodes, VLM nodes, pathfinding services, wallets, regions, and health checks.

## The Fit With Auki's Public Repos

Auki's public repositories already describe a distributed network made of many service types:

- [`posemesh`](https://github.com/aukilabs/posemesh): the main open-source Posemesh repository, describing a decentralized machine perception network and collaborative spatial computing protocol.
- [`domain-server`](https://github.com/aukilabs/domain-server): stores portal poses, spatial domain data, reconstructions, and occupancy maps. Its README describes public and dedicated operating modes and notes that each server needs a unique wallet to participate in the Posemesh economy.
- [`hagall`](https://github.com/aukilabs/hagall): the Relay server for real-time sessions, participants, entities, and message broadcasting.
- [`reconstruction-server`](https://github.com/aukilabs/reconstruction-server): a Posemesh reconstruction node used during domain setup.
- [`splatter-server`](https://github.com/aukilabs/splatter-server): a compute node for Gaussian splatting jobs in the reconstruction pipeline.
- [`vlm-node`](https://github.com/aukilabs/vlm-node): a Vision Language Model node with REST, WebSocket, queue, Docker, and Kubernetes deployment surfaces.
- [`LandmarkCalibrationSampleARKit`](https://github.com/aukilabs/LandmarkCalibrationSampleARKit): demonstrates Posemesh domains, portals, domain coordinates, and mobile calibration.
- [`pathfinding`](https://github.com/aukilabs/pathfinding): pathfinding libraries and a test application for navigation, accessibility, and robotics.

That shape suggests a practical need: software needs to discover which Posemesh services exist, who operates them, what they can do, where they are, and which keys identify them.

Today that discovery could be centralized in a console, an API, a database, a configuration file, or documentation. Those are all useful, but each is also a dependency. Handshake can add a decentralized discovery path that complements those systems instead of replacing them.

## What This Prototype Makes Useful

This prototype is useful if it is treated as a discovery and identity experiment, not as a browser naming experiment.

The useful claim is:

> A `.posemesh` Handshake name can be an owner-controlled discovery anchor for Posemesh services, operators, regions, and agents.

For example:

- `domains.posemesh` can publish domain manager endpoints.
- `relays.posemesh` can publish Relay/Hagall endpoints.
- `americaNorth.posemesh` can publish regional relays, bootstrap nodes, and compute services.
- `hq.posemesh` can publish a canonical Auki-operated manifest.
- `nils.posemesh` can publish a person, maintainer, test operator, or agent identity.

Those names are headless. Agents, CLIs, robots, services, and test tools can resolve and use them through DNS, resolver APIs, or Handshake-aware infrastructure. Browser support is a user-experience layer, not a hard requirement for the integration.

## Resilience Benefits

### 1. Fewer Single Points Of Discovery

If the only way to find Posemesh infrastructure is through one console, one API, or one domain, clients become dependent on that path. A Handshake-backed manifest gives clients another route to discover service endpoints and public keys.

This does not remove the need for Auki-operated services. It gives those services a more resilient way to announce themselves.

### 2. Stable Names For Moving Infrastructure

Service endpoints change. Regions are added. Operators rotate keys. Compute nodes come and go. A stable `.posemesh` name can keep the identity stable while the manifest changes.

That is especially relevant for:

- relays
- domain servers
- reconstruction nodes
- splatter nodes
- VLM nodes
- region-specific bootstrap nodes
- community-operated nodes

### 3. Better Operator Identity

The `domain-server` and `hagall` repos both indicate that servers need unique wallets to participate in the Posemesh economy. Handshake names could bind an operator name to:

- wallet references
- public keys
- service manifests
- health check endpoints
- supported capabilities
- region or locality metadata

This gives operators a readable persistent identity instead of only an endpoint URL or opaque wallet address.

### 4. Agent-Readable Network Metadata

Posemesh is naturally relevant to robots, AI agents, mapping tools, mobile devices, and spatial applications. Those systems should not have to scrape web pages or copy configuration from docs to discover network services.

The `agent-identity:v1` support in this prototype lets the same `.posemesh` naming layer describe agent-readable endpoints and capabilities.

### 5. Community Operations Without A Central Registry Bottleneck

If community operators run public domain servers, relays, or compute nodes, they need a way to publish discoverable metadata. Auki can still curate official lists, but Handshake gives operators a path to publish their own identity and capabilities.

This could support a layered model:

- Auki-operated names for canonical infrastructure.
- Region names for curated regional discovery.
- Operator-owned names for independent service identity.
- Client policy for deciding which names or keys to trust.

## Concrete Integration Ideas

### Domain Manager Discovery

Map `.posemesh` manifests to domain manager endpoints:

```txt
domains.posemesh TXT "posemesh:v1; manifest=https://example.com/posemesh/domains.json; capabilities=domain-discovery"
```

The manifest can list public and dedicated domain managers, regions, health checks, public keys, and wallet references.

### Relay Discovery

Map Relay/Hagall service discovery to names like:

- `relays.posemesh`
- `americaNorth.posemesh`
- `eu.posemesh`
- `asia.posemesh`

The manifest can list WebSocket endpoints, supported transports, session policies, regions, operator keys, and health endpoints.

### Compute Node Discovery

Add capability-specific service types. These are now represented directly in the prototype manifest schema:

- `reconstructionNodes`
- `splatterNodes`
- `vlmNodes`
- `pathfindingServices`

This would make discovery useful to `reconstruction-server`, `splatter-server`, `vlm-node`, `pathfinding`, and future node types.

### Official And Community Names

Use naming levels to separate trust:

- `hq.posemesh`: Auki-operated canonical manifest.
- `relays.posemesh`: curated relay directory.
- `domains.posemesh`: curated domain manager directory.
- `<operator>.posemesh`: independent operator identity.
- `<region>.posemesh`: region-specific bootstrap and service discovery.

## What Auki Would Need To Decide

This should not be treated as production-ready until Auki has made clear decisions about:

- metadata schema ownership and versioning
- which names are official, curated, or community-owned
- public key and wallet binding rules
- manifest signing and verification
- key rotation and revocation
- health check semantics
- endpoint freshness and cache TTLs
- fallback behavior when DNS, manifests, or signatures fail
- how this complements the Posemesh Console and existing APIs
- compatibility with SDKs and deployed node software

## Suggested Manifest Shape

The prototype now supports an Auki-facing manifest shape:

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

The important production step is still signature verification. TXT records can point to a manifest, but clients need a way to verify that the manifest was authorized by the expected `.posemesh` name or operator key.

## Suggested Adoption Path

### Phase 1: Prototype Review

Use this repository to discuss whether the discovery model is valuable. Keep it separate from official Auki SDKs.

### Phase 2: Schema Draft

Create a public metadata draft for `.posemesh` discovery records and manifests. Keep it small, versioned, and testable.

### Phase 3: Testnet Or Demo Names

Publish mock or experimental `.posemesh` records for a few names:

- `hq.posemesh`
- `domains.posemesh`
- `relays.posemesh`
- `americaNorth.posemesh`

### Phase 4: SDK Adapter

Build an optional adapter that can resolve `.posemesh` discovery manifests and feed endpoints into existing Posemesh clients.

### Phase 5: Production Hardening

Add signatures, trust policy, resolver redundancy, cache behavior, security review, and operational monitoring.

## Bottom Line

This integration is worth discussing because it addresses a real resilience question:

> If Posemesh is decentralized physical-world infrastructure, how do clients, agents, and operators discover the right services without depending on a single central directory?

Handshake is a plausible answer for the naming and discovery layer. Auki would still need production policy, signatures, service health, and SDK integration, but the direction is useful and aligned with the public shape of the Posemesh ecosystem.
