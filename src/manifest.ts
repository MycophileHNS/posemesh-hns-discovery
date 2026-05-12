import { lookup } from "node:dns/promises";
import { request } from "node:https";
import { isIP } from "node:net";
import { TextDecoder } from "node:util";
import { normalizeName } from "./name.ts";
import { parsePublicKey } from "./public-keys.ts";
import { verifySignedManifestEnvelopeText } from "./security.ts";
import type {
  BootstrapNode,
  DomainManager,
  FetchPosemeshManifestOptions,
  FetchedPosemeshManifest,
  ManifestHostResolver,
  ManifestHttpsRequest,
  ManifestResolvedAddress,
  ManifestSecurityMode,
  ManifestVerificationResult,
  ParseWarning,
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
const DEFAULT_MANIFEST_SECURITY_MODE: ManifestSecurityMode = "strict";
const DEFAULT_MANIFEST_MAX_CLOCK_SKEW_MS = 5 * 60 * 1000;
const DEFAULT_MANIFEST_MAX_TTL_MS = 24 * 60 * 60 * 1000;

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
  const fetched = await fetchPosemeshManifestWithVerification(url, options);
  return fetched.manifest;
}

/**
 * Fetch a Posemesh manifest over HTTPS, reject unsafe manifest hosts, and return
 * both the parsed manifest and its verification status. Strict mode is the default.
 */
export async function fetchPosemeshManifestWithVerification(
  url: string,
  options: FetchPosemeshManifestOptions = {},
): Promise<FetchedPosemeshManifest> {
  const manifestUrl = await assertSafeManifestUrl(
    url,
    options.resolveHostname ?? defaultManifestHostResolver,
  );

  const maxBytes = options.maxBytes ?? DEFAULT_MANIFEST_MAX_BYTES;
  const text = await fetchManifestText(
    manifestUrl.url,
    manifestUrl.addresses,
    options.timeoutMs ?? DEFAULT_MANIFEST_TIMEOUT_MS,
    maxBytes,
    options.httpsRequest ?? (request as ManifestHttpsRequest),
  );
  return parseFetchedManifestText(text, url, options);
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
    ...optionalUrlField(value, "manifestUrl", ["https:"]),
    ...optionalStringField(value, "issuedAt"),
    ...optionalStringField(value, "expiresAt"),
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
    publicKeys: parsePublicKeyArray(value.publicKeys, "publicKeys"),
    capabilities: parseStringArray(value.capabilities),
    ...optionalUrlField(value, "healthCheck", ["https:"]),
    ...optionalStringField(value, "signature"),
  };

  return manifest;
}

/**
 * Parse fetched manifest JSON and apply the requested security mode.
 *
 * - strict: require a valid signed envelope and a matching anchored key.
 * - permissive: allow unsigned manifests, but reject signed manifests that fail verification.
 * - demo: allow unsigned or invalid signed manifests and surface warnings for prototypes.
 */
export function parseFetchedManifestText(
  text: string,
  originalUrl: string,
  options: FetchPosemeshManifestOptions,
): FetchedPosemeshManifest {
  // This is the security boundary for fetched manifests. Strict mode fails closed by default.
  const mode = options.securityMode ?? DEFAULT_MANIFEST_SECURITY_MODE;
  const now = (options.now ?? (() => new Date()))();
  const parsed = JSON.parse(text) as unknown;

  if (mode === "strict") {
    return parseStrictFetchedManifest(text, originalUrl, options, now);
  }

  if (looksLikeSignedManifestEnvelope(parsed)) {
    try {
      return parseVerifiedFetchedManifest(text, originalUrl, options, now, true);
    } catch (error) {
      if (mode === "permissive") {
        const message = error instanceof Error ? error.message : "Unknown signature error.";
        throw new Error(`Permissive manifest verification failed for signed envelope: ${message}`);
      }

      return parseDemoInvalidSignedManifest(parsed, originalUrl, options, now, error);
    }
  }

  const unsignedManifest = parsePosemeshManifest(parsed);
  const verification = validateManifestSecurityClaims(
    unsignedManifest,
    {
      status: "unsigned-allowed",
      verifiedAt: now.toISOString(),
    },
    originalUrl,
    options,
    now,
    false,
  );
  const warnings = [
    createManifestWarning(
      originalUrl,
      `${mode} mode accepted an unsigned manifest. Strict mode requires a signed manifest envelope.`,
    ),
  ];

  return { manifest: unsignedManifest, verification, warnings };
}

function parseStrictFetchedManifest(
  text: string,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
): FetchedPosemeshManifest {
  const trustedKeys = options.trustedKeys ?? [];

  if (trustedKeys.length === 0) {
    throw new Error("Strict manifest verification requires at least one anchored or trusted key.");
  }

  try {
    return parseVerifiedFetchedManifest(text, manifestUrl, options, now, true);
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown signature error.";
    throw new Error(`Strict manifest verification failed: ${message}`, { cause: error });
  }
}

function parseVerifiedFetchedManifest(
  text: string,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  requireSignedClaims: boolean,
): FetchedPosemeshManifest {
  // A signature is only meaningful when it verifies against a key anchored by TXT or caller config.
  const trustedKeys = options.trustedKeys ?? [];

  if (trustedKeys.length === 0) {
    throw new Error("Manifest signature verification requires at least one anchored or trusted key.");
  }

  const verifiedEnvelope = verifySignedManifestEnvelopeText(text, trustedKeys, now);
  const manifest = parsePosemeshManifest(JSON.parse(verifiedEnvelope.payloadText) as unknown);
  const verification = validateManifestSecurityClaims(
    manifest,
    verifiedEnvelope.verification,
    manifestUrl,
    options,
    now,
    requireSignedClaims,
  );

  return { manifest, verification };
}

function parseDemoInvalidSignedManifest(
  parsed: unknown,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  verificationError: unknown,
): FetchedPosemeshManifest {
  const payloadText = decodeEnvelopePayloadText(parsed);
  const manifest = parsePosemeshManifest(JSON.parse(payloadText) as unknown);
  const envelopeMetadata = readEnvelopeMetadata(parsed);
  const verification = validateManifestSecurityClaims(
    manifest,
    {
      status: "invalid-allowed",
      ...(envelopeMetadata.algorithm ? { algorithm: envelopeMetadata.algorithm } : {}),
      ...(envelopeMetadata.keyId ? { keyId: envelopeMetadata.keyId } : {}),
      verifiedAt: now.toISOString(),
    },
    manifestUrl,
    options,
    now,
    false,
  );
  const message =
    verificationError instanceof Error ? verificationError.message : "Unknown signature error.";

  return {
    manifest,
    verification,
    warnings: [
      createManifestWarning(
        manifestUrl,
        `demo mode accepted a manifest with invalid signature verification: ${message}`,
      ),
    ],
  };
}

function looksLikeSignedManifestEnvelope(value: unknown): boolean {
  return (
    isRecord(value) &&
    ("payload" in value || "signature" in value || "algorithm" in value || "keyId" in value)
  );
}

function decodeEnvelopePayloadText(value: unknown): string {
  if (!isRecord(value) || typeof value.payload !== "string" || !value.payload.trim()) {
    throw new Error("Demo mode cannot read signed manifest payload.");
  }

  return decodeBase64Text(value.payload, "manifest envelope payload");
}

function readEnvelopeMetadata(value: unknown): {
  algorithm?: ManifestVerificationResult["algorithm"];
  keyId?: string;
} {
  if (!isRecord(value)) {
    return {};
  }

  return {
    ...(value.algorithm === "ed25519" || value.algorithm === "ecdsa-p256-sha256"
      ? { algorithm: value.algorithm }
      : {}),
    ...(typeof value.keyId === "string" && value.keyId.trim() ? { keyId: value.keyId.trim() } : {}),
  };
}

function decodeBase64Text(value: string, field: string): string {
  const trimmed = value.trim();

  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    throw new Error(`${field} must be base64 or base64url.`);
  }

  const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64").toString("utf8");
}

function createManifestWarning(url: string, message: string): ParseWarning {
  return {
    source: "manifest",
    url,
    message,
  };
}

function validateManifestSecurityClaims(
  manifest: PosemeshManifest,
  verification: ManifestVerificationResult,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  requireSignedClaims: boolean,
): ManifestVerificationResult {
  validateExpectedName(manifest, options.expectedName);
  validateExpectedManifestUrl(manifest, options.expectedManifestUrl ?? manifestUrl, requireSignedClaims);

  const issuedAt = validateManifestTimestamp(manifest.issuedAt, "issuedAt", requireSignedClaims);
  const expiresAt = validateManifestTimestamp(manifest.expiresAt, "expiresAt", requireSignedClaims);

  if (issuedAt && expiresAt) {
    validateManifestFreshness(issuedAt, expiresAt, now, options);
  }

  return {
    ...verification,
    ...(manifest.issuedAt ? { issuedAt: manifest.issuedAt } : {}),
    ...(manifest.expiresAt ? { expiresAt: manifest.expiresAt } : {}),
  };
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
    ...optionalPublicKeyField(value, "publicKey"),
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
    ...optionalPublicKeyField(item, "publicKey"),
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

function parsePublicKeyArray(value: unknown, field: string): string[] {
  return parseStringArray(value).map((item, index) =>
    parsePublicKey(item, `Manifest field ${field}[${index}]`),
  );
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

function optionalPublicKeyField<T extends string>(
  value: Record<string, unknown>,
  field: T,
): Partial<Record<T, string>> {
  const stringField = optionalStringField(value, field);
  const item = stringField[field];

  if (!item) {
    return {};
  }

  return { [field]: parsePublicKey(item, `Manifest field ${field}`) } as Partial<
    Record<T, string>
  >;
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

function validateExpectedName(manifest: PosemeshManifest, expectedName: string | undefined): void {
  if (!expectedName) {
    return;
  }

  if (!manifest.sourceName) {
    throw new Error(`Manifest sourceName is required and must match requested name ${expectedName}.`);
  }

  if (normalizeName(manifest.sourceName).toLowerCase() !== normalizeName(expectedName).toLowerCase()) {
    throw new Error(
      `Manifest sourceName ${manifest.sourceName} does not match requested name ${expectedName}.`,
    );
  }
}

function validateExpectedManifestUrl(
  manifest: PosemeshManifest,
  expectedManifestUrl: string | undefined,
  requireManifestUrl: boolean,
): void {
  if (!expectedManifestUrl) {
    return;
  }

  if (!manifest.manifestUrl) {
    if (requireManifestUrl) {
      throw new Error("Signed manifest payload must include manifestUrl.");
    }

    return;
  }

  if (normalizeUrlString(manifest.manifestUrl) !== normalizeUrlString(expectedManifestUrl)) {
    throw new Error(
      `Manifest manifestUrl ${manifest.manifestUrl} does not match requested URL ${expectedManifestUrl}.`,
    );
  }
}

function validateManifestTimestamp(
  value: string | undefined,
  field: "issuedAt" | "expiresAt",
  required: boolean,
): Date | undefined {
  if (!value) {
    if (required) {
      throw new Error(`Signed manifest payload must include ${field}.`);
    }

    return undefined;
  }

  const parsed = new Date(value);

  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw new Error(`Manifest ${field} must be a valid ISO-8601 UTC timestamp.`);
  }

  return parsed;
}

function validateManifestFreshness(
  issuedAt: Date,
  expiresAt: Date,
  now: Date,
  options: FetchPosemeshManifestOptions,
): void {
  const maxClockSkewMs = options.maxClockSkewMs ?? DEFAULT_MANIFEST_MAX_CLOCK_SKEW_MS;
  const maxManifestTtlMs = options.maxManifestTtlMs ?? DEFAULT_MANIFEST_MAX_TTL_MS;
  const ttlMs = expiresAt.getTime() - issuedAt.getTime();

  if (ttlMs <= 0) {
    throw new Error("Manifest expiresAt must be after issuedAt.");
  }

  if (ttlMs > maxManifestTtlMs) {
    throw new Error(`Manifest validity window must not exceed ${maxManifestTtlMs}ms.`);
  }

  if (issuedAt.getTime() - maxClockSkewMs > now.getTime()) {
    throw new Error("Manifest is not valid yet.");
  }

  if (expiresAt.getTime() + maxClockSkewMs < now.getTime()) {
    throw new Error("Manifest has expired.");
  }
}

function normalizeUrlString(value: string): string {
  return new URL(value).toString();
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

interface SafeManifestUrl {
  url: URL;
  addresses: ManifestResolvedAddress[];
}

async function assertSafeManifestUrl(
  url: string,
  resolveHostname: ManifestHostResolver,
): Promise<SafeManifestUrl> {
  let parsed: URL;

  try {
    parsed = new URL(url);
  } catch {
    throw new Error(`Manifest URL is invalid: ${url}`);
  }

  if (!isAllowedProtocol(parsed.protocol, ["https:"])) {
    throw new Error("Manifest URL must use https.");
  }

  const addresses = await assertPublicManifestHost(parsed.hostname, resolveHostname);
  return { url: parsed, addresses };
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
): Promise<ManifestResolvedAddress[]> {
  // Resolve first, then reject the whole manifest URL if any returned address is unsafe.
  const host = normalizeHost(hostname);

  if (isLocalOrPrivateHost(host)) {
    throw new Error("Manifest URL must not use localhost, private, or reserved network addresses.");
  }

  const ipVersion = isIP(host);

  if (ipVersion) {
    return [{ address: host, family: ipVersion === 6 ? 6 : 4 }];
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

  const normalizedAddresses = addresses.map(({ address }) => {
    const normalizedAddress = normalizeHost(address);
    const resolvedFamily = isIP(normalizedAddress);

    if (!resolvedFamily) {
      throw new Error(`Manifest host ${host} resolves to an invalid IP address.`);
    }

    return {
      address: normalizedAddress,
      family: resolvedFamily === 6 ? 6 : 4,
    } satisfies ManifestResolvedAddress;
  });

  const blockedAddress = normalizedAddresses.find(({ address }) => isLocalOrPrivateHost(address));

  if (blockedAddress) {
    throw new Error(`Manifest host ${host} resolves to a localhost, private, or reserved network address.`);
  }

  return normalizedAddresses;
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
  const mappedIpv4 = parseIpv4MappedIpv6(host);

  if (mappedIpv4) {
    return isPrivateIpv4(mappedIpv4);
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

function parseIpv4MappedIpv6(host: string): string | undefined {
  const dotted = host.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);

  if (dotted?.[1]) {
    return dotted[1];
  }

  const hexadecimal = host.match(/^::ffff:([0-9a-f]{1,4}):([0-9a-f]{1,4})$/i);

  if (!hexadecimal?.[1] || !hexadecimal[2]) {
    return undefined;
  }

  const high = Number.parseInt(hexadecimal[1], 16);
  const low = Number.parseInt(hexadecimal[2], 16);

  return [high >> 8, high & 0xff, low >> 8, low & 0xff].join(".");
}

function fetchManifestText(
  url: URL,
  addresses: ManifestResolvedAddress[],
  timeoutMs: number,
  maxBytes: number,
  httpsRequest: ManifestHttpsRequest,
): Promise<string> {
  return tryManifestAddresses(url, addresses, timeoutMs, maxBytes, httpsRequest);
}

async function tryManifestAddresses(
  url: URL,
  addresses: ManifestResolvedAddress[],
  timeoutMs: number,
  maxBytes: number,
  httpsRequest: ManifestHttpsRequest,
): Promise<string> {
  // Try resolved addresses one at a time so a dead address does not fail the whole manifest.
  const errors: string[] = [];

  for (const address of addresses) {
    try {
      return await fetchManifestTextFromAddress(url, address, timeoutMs, maxBytes, httpsRequest);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unknown manifest fetch error.";
      errors.push(`${address.address}: ${message}`);
    }
  }

  throw new Error(
    `Manifest fetch failed for ${url.toString()} using ${addresses.length} resolved address(es): ${errors.join("; ")}`,
  );
}

function fetchManifestTextFromAddress(
  url: URL,
  address: ManifestResolvedAddress,
  timeoutMs: number,
  maxBytes: number,
  httpsRequest: ManifestHttpsRequest,
): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    const decoder = new TextDecoder();
    let bytesRead = 0;

    const req = httpsRequest(
      {
        protocol: url.protocol,
        hostname: url.hostname,
        port: url.port,
        path: `${url.pathname}${url.search}`,
        method: "GET",
        headers: {
          accept: "application/json",
          host: url.host,
        },
        servername: isIP(normalizeHost(url.hostname)) ? undefined : url.hostname,
        lookup: (_hostname, _options, callback) => {
          callback(null, address.address, address.family);
        },
      },
      (response) => {
        const statusCode = response.statusCode ?? 0;

        if (statusCode >= 300 && statusCode < 400) {
          response.resume();
          reject(new Error(`Manifest fetch failed for ${url.toString()}: redirects are not allowed.`));
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          response.resume();
          reject(new Error(`Manifest fetch failed for ${url.toString()}: HTTP ${statusCode}`));
          return;
        }

        const contentType = response.headers["content-type"];
        const declaredContentType = Array.isArray(contentType) ? contentType[0] : contentType;

        if (!isJsonContentType(declaredContentType)) {
          response.resume();
          reject(
            new Error(
              `Manifest response for ${url.toString()} must use Content-Type application/json.`,
            ),
          );
          return;
        }

        const contentLength = response.headers["content-length"];
        const declaredLength = Array.isArray(contentLength) ? contentLength[0] : contentLength;

        if (declaredLength && Number(declaredLength) > maxBytes) {
          response.resume();
          reject(new Error(`Manifest response is larger than ${maxBytes} bytes.`));
          return;
        }

        response.on("data", (chunk: Uint8Array) => {
          bytesRead += chunk.byteLength;

          if (bytesRead > maxBytes) {
            req.destroy(new Error(`Manifest response is larger than ${maxBytes} bytes.`));
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", () => {
          resolve(decoder.decode(Buffer.concat(chunks)));
        });

        response.on("error", reject);
      },
    );

    req.setTimeout(timeoutMs, () => {
      req.destroy(new Error(`Manifest fetch timed out after ${timeoutMs}ms.`));
    });

    req.on("error", reject);
    req.end();
  });
}

function isJsonContentType(contentType: string | undefined): boolean {
  if (!contentType) {
    return false;
  }

  const [mediaType] = contentType.split(";", 1);
  return mediaType?.trim().toLowerCase() === "application/json";
}
