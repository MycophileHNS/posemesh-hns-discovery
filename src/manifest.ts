import type {
  BootstrapNode,
  DomainManager,
  PosemeshManifest,
  Relay,
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
    domainManagers: parseDomainManagers(value.domainManagers),
    relays: parseRelays(value.relays),
    bootstrapNodes: parseBootstrapNodes(value.bootstrapNodes),
    publicKeys: parseStringArray(value.publicKeys),
    capabilities: parseStringArray(value.capabilities),
    ...optionalStringField(value, "signature"),
  };

  // TODO: Prototype only. Production code should verify manifest signatures
  // against keys anchored in Handshake TXT records or another trusted policy.
  return manifest;
}

function parseDomainManagers(value: unknown): DomainManager[] {
  return parseObjectArray(value, "domainManagers").map((item) => ({
    ...optionalStringField(item, "id"),
    ...optionalStringField(item, "name"),
    endpoint: requiredStringField(item, "endpoint", "domainManagers"),
    ...optionalStringField(item, "region"),
    ...optionalStringField(item, "publicKey"),
    capabilities: parseStringArray(item.capabilities),
  }));
}

function parseRelays(value: unknown): Relay[] {
  return parseObjectArray(value, "relays").map((item) => ({
    ...optionalStringField(item, "id"),
    endpoint: requiredStringField(item, "endpoint", "relays"),
    ...optionalStringField(item, "region"),
    ...optionalStringField(item, "transport"),
    ...optionalStringField(item, "publicKey"),
  }));
}

function parseBootstrapNodes(value: unknown): BootstrapNode[] {
  return parseObjectArray(value, "bootstrapNodes").map((item) => ({
    ...optionalStringField(item, "id"),
    endpoint: requiredStringField(item, "endpoint", "bootstrapNodes"),
    ...optionalStringField(item, "transport"),
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
