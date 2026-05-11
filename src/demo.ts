import type { PosemeshManifest } from "./types.ts";

const HQ_TXT_KEY = "02aa";
const HQ_DOMAIN_KEY = "02bb";
const HQ_RELAY_KEY = "02cc";
const HQ_RECONSTRUCTION_KEY = "02dd";
const NILS_AGENT_KEY = "02ee";
const AMERICA_NORTH_KEY = "02ff";
const RELAY_DIRECTORY_KEY = "03aa";
const DOMAIN_DIRECTORY_KEY = "03bb";

export const demoTxtRecords: Record<string, string[]> = {
  "hq.posemesh": [
    `posemesh:v1; manifest=https://example.com/posemesh/hq.json; publicKey=${HQ_TXT_KEY}; capabilities=domain-discovery,relay-discovery`,
  ],
  "nils.posemesh": [
    `agent-identity:v1={"version":1,"endpoint":"https://example.com/posemesh/nils-agent.json","publicKey":"${NILS_AGENT_KEY}","capabilities":["domain-discovery","personal-agent"]}`,
    `posemesh:v1; manifest=https://example.com/posemesh/nils-agent.json; publicKey=${NILS_AGENT_KEY}; capabilities=domain-discovery,personal-agent`,
  ],
  "americaNorth.posemesh": [
    `posemesh:v1; manifest=https://example.com/posemesh/america-north.json; publicKey=${AMERICA_NORTH_KEY}; capabilities=relay-discovery,regional-bootstrap`,
  ],
  "relays.posemesh": [
    `posemesh:v1; manifest=https://example.com/posemesh/relays.json; publicKey=${RELAY_DIRECTORY_KEY}; capabilities=relay-discovery`,
  ],
  "domains.posemesh": [
    `posemesh:v1; manifest=https://example.com/posemesh/domains.json; publicKey=${DOMAIN_DIRECTORY_KEY}; capabilities=domain-discovery`,
  ],
};

export const demoManifests: Record<string, PosemeshManifest> = {
  "https://example.com/posemesh/hq.json": {
    version: 1,
    sourceName: "hq.posemesh",
    regions: ["global"],
    domainManagers: [
      {
        id: "hq-domain-manager",
        name: "Posemesh HQ domain manager",
        endpoint: "https://hq.example.com/domain-manager",
        region: "global",
        publicKey: HQ_DOMAIN_KEY,
        capabilities: ["domain-discovery"],
        healthCheck: "https://hq.example.com/domain-manager/health",
      },
    ],
    relays: [
      {
        id: "hq-relay",
        endpoint: "wss://hq.example.com/relay",
        region: "global",
        transport: "wss",
        publicKey: HQ_RELAY_KEY,
        capabilities: ["relay-discovery"],
      },
    ],
    reconstructionNodes: [
      {
        id: "hq-reconstruction",
        endpoint: "https://reconstruction.example.com/jobs",
        region: "global",
        transport: "https",
        publicKey: HQ_RECONSTRUCTION_KEY,
        capabilities: ["reconstruction"],
      },
    ],
    splatterNodes: [
      {
        id: "hq-splatter",
        endpoint: "https://splatter.example.com/jobs",
        region: "global",
        transport: "https",
        capabilities: ["gaussian-splatting"],
      },
    ],
    vlmNodes: [
      {
        id: "hq-vlm",
        endpoint: "wss://vlm.example.com/api/v1/ws",
        region: "global",
        transport: "wss",
        capabilities: ["vlm-inference"],
        models: ["moondream:1.8b"],
      },
    ],
    pathfindingServices: [
      {
        id: "hq-pathfinding",
        endpoint: "https://pathfinding.example.com/route",
        region: "global",
        transport: "https",
        capabilities: ["pathfinding"],
      },
    ],
    bootstrapNodes: [
      {
        id: "hq-bootstrap",
        endpoint: "https://hq.example.com/bootstrap",
        transport: "https",
      },
    ],
    wallets: [
      {
        address: "auki-wallet-demo-hq",
        chain: "posemesh",
        role: "operator",
      },
    ],
    publicKeys: [HQ_TXT_KEY],
    capabilities: [
      "domain-discovery",
      "relay-discovery",
      "reconstruction",
      "gaussian-splatting",
      "vlm-inference",
      "pathfinding",
    ],
    healthCheck: "https://hq.example.com/health",
  },
  "https://example.com/posemesh/nils-agent.json": {
    version: 1,
    sourceName: "nils.posemesh",
    regions: ["personal"],
    domainManagers: [
      {
        id: "nils-domain-manager",
        endpoint: "https://nils.example.com/domains",
        capabilities: ["domain-discovery"],
      },
    ],
    relays: [],
    bootstrapNodes: [
      {
        id: "nils-bootstrap",
        endpoint: "https://nils.example.com/bootstrap",
        transport: "https",
      },
    ],
    wallets: [
      {
        address: "nils-wallet-demo",
        chain: "posemesh",
        role: "operator",
      },
    ],
    publicKeys: [NILS_AGENT_KEY],
    capabilities: ["domain-discovery", "personal-agent"],
  },
  "https://example.com/posemesh/america-north.json": {
    version: 1,
    sourceName: "americaNorth.posemesh",
    regions: ["north-america"],
    domainManagers: [],
    relays: [
      {
        id: "america-north-relay-1",
        endpoint: "wss://na1.example.com/posemesh-relay",
        region: "North America",
        transport: "wss",
        capabilities: ["relay-discovery"],
      },
      {
        id: "america-north-relay-2",
        endpoint: "wss://na2.example.com/posemesh-relay",
        region: "North America",
        transport: "wss",
        capabilities: ["relay-discovery"],
      },
    ],
    reconstructionNodes: [
      {
        id: "america-north-reconstruction",
        endpoint: "https://na-reconstruction.example.com/jobs",
        region: "North America",
        transport: "https",
        capabilities: ["reconstruction"],
      },
    ],
    splatterNodes: [
      {
        id: "america-north-splatter",
        endpoint: "https://na-splatter.example.com/jobs",
        region: "North America",
        transport: "https",
        capabilities: ["gaussian-splatting"],
      },
    ],
    bootstrapNodes: [
      {
        id: "america-north-bootstrap",
        endpoint: "https://na.example.com/bootstrap",
        transport: "https",
      },
    ],
    publicKeys: [AMERICA_NORTH_KEY],
    capabilities: ["relay-discovery", "regional-bootstrap", "reconstruction", "gaussian-splatting"],
    healthCheck: "https://na.example.com/health",
  },
  "https://example.com/posemesh/relays.json": {
    version: 1,
    sourceName: "relays.posemesh",
    regions: ["global"],
    relays: [
      {
        id: "relay-directory",
        endpoint: "https://relays.example.com/directory.json",
        transport: "https",
        capabilities: ["relay-discovery"],
      },
    ],
    bootstrapNodes: [],
    publicKeys: [RELAY_DIRECTORY_KEY],
    capabilities: ["relay-discovery"],
  },
  "https://example.com/posemesh/domains.json": {
    version: 1,
    sourceName: "domains.posemesh",
    regions: ["global"],
    domainManagers: [
      {
        id: "domain-directory",
        endpoint: "https://domains.example.com/managers.json",
        capabilities: ["domain-discovery"],
      },
    ],
    relays: [],
    bootstrapNodes: [],
    publicKeys: [DOMAIN_DIRECTORY_KEY],
    capabilities: ["domain-discovery"],
  },
};

export async function demoManifestFetcher(url: string): Promise<PosemeshManifest> {
  const manifest = demoManifests[url];

  if (!manifest) {
    throw new Error(`Demo manifest not found for ${url}`);
  }

  return manifest;
}

export const demoNames = Object.keys(demoTxtRecords);
