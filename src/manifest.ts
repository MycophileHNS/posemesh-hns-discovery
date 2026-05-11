import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type {
  BootstrapNode,
  DomainManager,
  FetchPosemeshManifestOptions,
  ManifestHostResolver,
  PathfindingService,
  PosemeshManifest,
  PosemeshServiceEndpoint,
  ReconstructionNode,
  Relay,
  SplatterNode,
  VlmNode,
  WalletReference,
} from "./types.ts";

const DEFAULT_MANIFEST_TIMEOUT_MS = 5_000;
const DEFAULT_MANIFEST_MAX_BYTES = 128 * 1024;

const defaultManifestHostResolver: ManifestHostResolver = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address, family }) => ({
    address,
    family: family === 6 ? 6 : 4,
  }));
};

export async function fetchPosemeshManifest(
  url: string,
  options: FetchPosemeshManifestOptions = {},
): Promise<PosemeshManifest> {
  const manifestUrl = await assertSafeManifestUrl(
    url,
    options.resolveHostname ?? defaultManifestHostResolver,
  );

  const maxBytes = options.maxBytes ?? DEFAULT_MANIFEST_MAX_BYTES;
  const response = await fetch(manifestUrl, {
    headers: {
      accept: "application/json",
    },
    redirect: "error",
    signal: AbortSignal.timeout(options.timeoutMs ?? DEFAULT_MANIFEST_TIMEOUT_MS),
  });

  if (!response.ok) {
    throw new Error(`Manifest fetch failed for ${url}: HTTP ${response.status}`);
  }

  const json = JSON.parse(await readLimitedText(response, maxBytes)) as unknown;
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
    ...optionalUrlField(value, "healthCheck", ["https:"]),
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
    endpoint: requiredUrlField(value, "endpoint", field, ["https:", "wss:"]),
    ...optionalStringField(value, "region"),
    ...optionalStringField(value, "transport"),
    ...optionalStringField(value, "publicKey"),
    capabilities: parseStringArray(value.capabilities),
    ...optionalUrlField(value, "healthCheck", ["https:"]),
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

  return value.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`Manifest string list item ${index} must be a non-empty string.`);
    }

    return item.trim();
  });
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

function requiredUrlField(
  value: Record<string, unknown>,
  field: string,
  parent: string,
  protocols: string[],
): string {
  return validateUrl(requiredStringField(value, field, parent), `${parent}.${field}`, protocols);
}

function optionalStringField<T extends string>(
  value: Record<string, unknown>,
  field: T,
): Partial<Record<T, string>> {
  const item = value[field];

  if (item === undefined) {
    return {};
  }

  if (typeof item !== "string" || !item.trim()) {
    throw new Error(`Manifest field ${field} must be a non-empty string.`);
  }

  return { [field]: item.trim() } as Partial<Record<T, string>>;
}

function optionalUrlField<T extends string>(
  value: Record<string, unknown>,
  field: T,
  protocols: string[],
): Partial<Record<T, string>> {
  const stringField = optionalStringField(value, field);
  const item = stringField[field];

  if (!item) {
    return {};
  }

  return {
    [field]: validateUrl(item, field, protocols),
  } as Partial<Record<T, string>>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

async function assertSafeManifestUrl(
  url: string,
  resolveHostname: ManifestHostResolver,
): Promise<URL> {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Manifest URL is invalid: ${url}`);
  }

  if (!isAllowedProtocol(parsed.protocol, ["https:"])) {
    throw new Error("Manifest URL must use https.");
  }

  await assertPublicManifestHost(parsed.hostname, resolveHostname);
  return parsed;
}

function validateUrl(url: string, field: string, protocols: string[]): string {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Manifest field ${field} must be a valid URL.`);
  }

  if (!isAllowedProtocol(parsed.protocol, protocols)) {
    throw new Error(`Manifest field ${field} must use ${protocols.join(" or ")}.`);
  }

  return url;
}

function isAllowedProtocol(protocol: string, protocols: string[]): boolean {
  return protocols.includes(protocol);
}

async function assertPublicManifestHost(
  hostname: string,
  resolveHostname: ManifestHostResolver,
): Promise<void> {
  const host = normalizeHost(hostname);

  if (isLocalOrPrivateHost(host)) {
    throw new Error("Manifest URL must not use localhost, private, or reserved network addresses.");
  }

  if (isIP(host)) {
    return;
  }

  let addresses: Awaited<ReturnType<ManifestHostResolver>>;

  try {
    addresses = await resolveHostname(host);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown host lookup error.";
    throw new Error(`Manifest host lookup failed for ${host}: ${message}`);
  }

  if (addresses.length === 0) {
    throw new Error(`Manifest host lookup returned no addresses for ${host}.`);
  }

  const blockedAddress = addresses.find(({ address }) => isLocalOrPrivateHost(address));

  if (blockedAddress) {
    throw new Error(
      `Manifest host ${host} resolves to a localhost, private, or reserved network address.`,
    );
  }
}

function normalizeHost(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function isLocalOrPrivateHost(hostname: string): boolean {
  const host = normalizeHost(hostname);

  if (host === "localhost" || host.endsWith(".localhost")) {
    return true;
  }

  const ipVersion = isIP(host);

  if (ipVersion === 4) {
    return isPrivateIpv4(host);
  }

  if (ipVersion === 6) {
    return isPrivateIpv6(host);
  }

  return false;
}

function isPrivateIpv4(host: string): boolean {
  const [first = 0, second = 0, third = 0] = host.split(".").map((part) => Number(part));

  return (
    first === 0 ||
    first === 10 ||
    (first === 100 && second >= 64 && second <= 127) ||
    first === 127 ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0 && (third === 0 || third === 2)) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    (first === 198 && second === 51 && third === 100) ||
    (first === 203 && second === 0 && third === 113) ||
    first >= 224
  );
}

function isPrivateIpv6(host: string): boolean {
  const mappedIpv4 = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);

  if (mappedIpv4?.[1]) {
    return isPrivateIpv4(mappedIpv4[1]);
  }

  return (
    host === "::" ||
    host === "::1" ||
    host.startsWith("fc") ||
    host.startsWith("fd") ||
    host.startsWith("fe8") ||
    host.startsWith("fe9") ||
    host.startsWith("fea") ||
    host.startsWith("feb") ||
    host.startsWith("2001:db8")
  );
}

async function readLimitedText(response: Response, maxBytes: number): Promise<string> {
  const contentLength = response.headers.get("content-length");

  if (contentLength && Number(contentLength) > maxBytes) {
    throw new Error(`Manifest response is larger than ${maxBytes} bytes.`);
  }

  if (!response.body) {
    return "";
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let bytesRead = 0;
  let text = "";

  while (true) {
    const { done, value } = await reader.read();

    if (done) {
      return text + decoder.decode();
    }

    bytesRead += value.byteLength;

    if (bytesRead > maxBytes) {
      await reader.cancel();
      throw new Error(`Manifest response is larger than ${maxBytes} bytes.`);
    }

    text += decoder.decode(value, { stream: true });
  }
}
