import type {
  BootstrapNode,
  DomainManager,
  PathfindingService,
  PosemeshManifest,
  PosemeshServiceEndpoint,
  ReconstructionNode,
  Relay,
  SplatterNode,
  VlmNode,
  WalletReference,
} from "./types.ts";

export async function fetchPosemeshManifest(url: string): Promise<PosemeshManifest> {
  const response = await fetch(url, {
    headers: {
      accept: "application/json",
    },
  });

  if (!response.ok) {
    throw new Error(`Manifest fetch failed for ${url}: HTTP ${response.status}`);
  }

  const json = await response.json();
  return parsePosemeshManifest(json);
}

export function parsePosemeshManifest(value: unknown): PosemeshManifest {
  if (!isRecord(value)) {
    throw new Error("Manifest must be a JSON object.");
  }

  if (value.version !== 1) {
    throw new Error("Manifest version must be 1.");
  }

  const manifest: PosemeshManifest = {
    version: 1,
    ...optionalStringField(value, "name"),
    ...optionalStringField(value, "sourceName"),
    regions: parseStringArray(value.regions),
    domainManagers: parseDomainManagers(value.domainManagers),
    relays: parseRelays(value.relays),
    reconstructionNodes: parseServiceEndpoints<ReconstructionNode>(
      value.reconstructionNodes,
      "reconstructionNodes",
    ),
    splatterNodes: parseServiceEndpoints<SplatterNode>(value.splatterNodes, "splatterNodes"),
    vlmNodes: parseVlmNodes(value.vlmNodes),
    pathfindingServices: parseServiceEndpoints<PathfindingService>(
      value.pathfindingServices,
      "pathfindingServices",
    ),
    bootstrapNodes: parseBootstrapNodes(value.bootstrapNodes),
    wallets: parseWallets(value.wallets),
    publicKeys: parseStringArray(value.publicKeys),
    capabilities: parseStringArray(value.capabilities),
    ...optionalStringField(value, "healthCheck"),
    ...optionalStringField(value, "signature"),
  };

  // TODO: Prototype only. Production code should verify manifest signatures
  // against keys anchored in Handshake TXT records or another trusted policy.
  return manifest;
}

function parseDomainManagers(value: unknown): DomainManager[] {
  return parseObjectArray(value, "domainManagers").map((item) => {
    return {
      ...parseServiceEndpoint<DomainManager>(item, "domainManagers"),
      ...optionalStringField(item, "wallet"),
    };
  });
}

function parseRelays(value: unknown): Relay[] {
  return parseObjectArray(value, "relays").map((item) => {
    return {
      ...parseServiceEndpoint<Relay>(item, "relays"),
      ...optionalStringField(item, "sessionPolicy"),
    };
  });
}

function parseBootstrapNodes(value: unknown): BootstrapNode[] {
  return parseServiceEndpoints<BootstrapNode>(value, "bootstrapNodes");
}

function parseVlmNodes(value: unknown): VlmNode[] {
  return parseObjectArray(value, "vlmNodes").map((item) => {
    const models = parseStringArray(item.models);

    return {
      ...parseServiceEndpoint<VlmNode>(item, "vlmNodes"),
      ...(models.length > 0 ? { models } : {}),
    };
  });
}

function parseServiceEndpoints<T extends PosemeshServiceEndpoint>(
  value: unknown,
  field: string,
): T[] {
  return parseObjectArray(value, field).map((item) => parseServiceEndpoint<T>(item, field));
}

function parseServiceEndpoint<T extends PosemeshServiceEndpoint>(
  value: Record<string, unknown>,
  field: string,
): T {
  const endpoint: PosemeshServiceEndpoint = {
    ...optionalStringField(value, "id"),
    ...optionalStringField(value, "name"),
    endpoint: requiredStringField(value, "endpoint", field),
    ...optionalStringField(value, "region"),
    ...optionalStringField(value, "transport"),
    ...optionalStringField(value, "publicKey"),
    capabilities: parseStringArray(value.capabilities),
    ...optionalStringField(value, "healthCheck"),
  };

  return endpoint as T;
}

function parseWallets(value: unknown): WalletReference[] {
  return parseObjectArray(value, "wallets").map((item) => ({
    address: requiredStringField(item, "address", "wallets"),
    ...optionalStringField(item, "chain"),
    ...optionalStringField(item, "role"),
    ...optionalStringField(item, "publicKey"),
  }));
}

function parseObjectArray(value: unknown, field: string): Record<string, unknown>[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`Manifest field ${field} must be an array.`);
  }

  return value.map((item, index) => {
    if (!isRecord(item)) {
      throw new Error(`Manifest field ${field}[${index}] must be an object.`);
    }

    return item;
  });
}

function parseStringArray(value: unknown): string[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error("Manifest string list must be an array.");
  }

  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function requiredStringField(
  value: Record<string, unknown>,
  field: string,
  parent: string,
): string {
  const item = value[field];

  if (typeof item !== "string" || !item.trim()) {
    throw new Error(`Manifest field ${parent}.${field} is required.`);
  }

  return item.trim();
}

function optionalStringField<T extends string>(
  value: Record<string, unknown>,
  field: T,
): Partial<Record<T, string>> {
  const item = value[field];

  if (typeof item !== "string" || !item.trim()) {
    return {};
  }

  return { [field]: item.trim() } as Partial<Record<T, string>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
