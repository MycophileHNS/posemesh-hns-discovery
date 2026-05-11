import type { PosemeshManifest } from "./types.ts";

export const demoTxtRecords: Record<string, string[]> = {
  "hq.posemesh": [
    "posemesh:v1; manifest=https://example.com/posemesh/hq.json; publicKey=02HQPOSEMESHDEMO; capabilities=domain-discovery,relay-discovery",
  ],
  "nils.posemesh": [
    "agent-identity:v1={\"version\":1,\"endpoint\":\"https://example.com/posemesh/nils-agent.json\",\"capabilities\":[\"domain-discovery\",\"personal-agent\"]}",
  ],
  "americaNorth.posemesh": [
    "posemesh:v1; manifest=https://example.com/posemesh/america-north.json; publicKey=02AMERICANORTHPOSEMESH; capabilities=relay-discovery,regional-bootstrap",
  ],
  "relays.posemesh": [
    "posemesh:v1; manifest=https://example.com/posemesh/relays.json; publicKey=02RELAYPOSEMESHDEMO; capabilities=relay-discovery",
  ],
  "domains.posemesh": [
    "posemesh:v1; manifest=https://example.com/posemesh/domains.json; publicKey=02DOMAINPOSEMESHDEMO; capabilities=domain-discovery",
  ],
};

export const demoManifests: Record<string, PosemeshManifest> = {
  "https://example.com/posemesh/hq.json": {
    version: 1,
    sourceName: "hq.posemesh",
    domainManagers: [
      {
        id: "hq-domain-manager",
        name: "Posemesh HQ domain manager",
        endpoint: "https://hq.example.com/domain-manager",
        region: "global",
        publicKey: "02HQDOMAINMANAGER",
        capabilities: ["domain-discovery"],
      },
    ],
    relays: [
      {
        id: "hq-relay",
        endpoint: "wss://hq.example.com/relay",
        region: "global",
        transport: "wss",
        publicKey: "02HQRELAY",
      },
    ],
    bootstrapNodes: [
      {
        id: "hq-bootstrap",
        endpoint: "https://hq.example.com/bootstrap",
        transport: "https",
      },
    ],
    publicKeys: ["02HQPOSEMESHDEMO"],
    capabilities: ["domain-discovery", "relay-discovery"],
  },
  "https://example.com/posemesh/nils-agent.json": {
    version: 1,
    sourceName: "nils.posemesh",
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
    publicKeys: ["02NILSAGENT"],
    capabilities: ["domain-discovery", "personal-agent"],
  },
  "https://example.com/posemesh/america-north.json": {
    version: 1,
    sourceName: "americaNorth.posemesh",
    domainManagers: [],
    relays: [
      {
        id: "america-north-relay-1",
        endpoint: "wss://na1.example.com/posemesh-relay",
        region: "North America",
        transport: "wss",
      },
      {
        id: "america-north-relay-2",
        endpoint: "wss://na2.example.com/posemesh-relay",
        region: "North America",
        transport: "wss",
      },
    ],
    bootstrapNodes: [
      {
        id: "america-north-bootstrap",
        endpoint: "https://na.example.com/bootstrap",
        transport: "https",
      },
    ],
    publicKeys: ["02AMERICANORTHPOSEMESH"],
    capabilities: ["relay-discovery", "regional-bootstrap"],
  },
  "https://example.com/posemesh/relays.json": {
    version: 1,
    sourceName: "relays.posemesh",
    relays: [
      {
        id: "relay-directory",
        endpoint: "https://relays.example.com/directory.json",
        transport: "https",
      },
    ],
    bootstrapNodes: [],
    publicKeys: ["02RELAYPOSEMESHDEMO"],
    capabilities: ["relay-discovery"],
  },
  "https://example.com/posemesh/domains.json": {
    version: 1,
    sourceName: "domains.posemesh",
    domainManagers: [
      {
        id: "domain-directory",
        endpoint: "https://domains.example.com/managers.json",
        capabilities: ["domain-discovery"],
      },
    ],
    relays: [],
    bootstrapNodes: [],
    publicKeys: ["02DOMAINPOSEMESHDEMO"],
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
