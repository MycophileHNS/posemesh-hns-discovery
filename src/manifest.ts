import { lookup } from "node:dns/promises";
import { createHash, X509Certificate } from "node:crypto";
import { request } from "node:https";
import { isIP } from "node:net";
import { TextDecoder } from "node:util";
import { normalizeName } from "./name.ts";
import {
  createWarning,
  discoveryError,
  errorLogFields,
  getErrorCode,
  getErrorMessage,
  logDebug,
  logError,
  logInfo,
  logWarn,
} from "./observability.ts";
import { parsePublicKey } from "./public-keys.ts";
import { verifySignedManifestEnvelopeText } from "./security.ts";
import type {
  BootstrapNode,
  DiscoveryErrorCode,
  DiscoveryLogger,
  DomainManager,
  FetchPosemeshManifestOptions,
  FetchedPosemeshManifest,
  LoggerRedactionOptions,
  ManifestCacheMetadata,
  ManifestDaneMetadata,
  ManifestHostResolver,
  ManifestHttpsRequest,
  ManifestLimits,
  ManifestResolvedAddress,
  ManifestSecurityMode,
  ManifestTlsaRecord,
  ManifestTlsaResolver,
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

interface ResolvedManifestLimits {
  maxStringBytes: number;
  maxUrlBytes: number;
  maxArrayItems: number;
  maxCapabilities: number;
  maxPublicKeys: number;
  maxServicesPerCategory: number;
  maxTotalServices: number;
  maxWallets: number;
  maxRegions: number;
  maxAudience: number;
  maxModels: number;
}

const DEFAULT_MANIFEST_LIMITS: ResolvedManifestLimits = {
  maxStringBytes: 2_048,
  maxUrlBytes: 4_096,
  maxArrayItems: 128,
  maxCapabilities: 128,
  maxPublicKeys: 32,
  maxServicesPerCategory: 64,
  maxTotalServices: 256,
  maxWallets: 64,
  maxRegions: 64,
  maxAudience: 16,
  maxModels: 32,
};

interface ManifestFetchPolicy {
  timeoutMs: number;
  maxBytes: number;
  httpsRequest: ManifestHttpsRequest;
  tlsPins?: Record<string, string[]>;
  enableDane: boolean;
  requireTlsa: boolean;
  resolveTlsa: ManifestTlsaResolver;
  securityMode: ManifestSecurityMode;
  checkedAt: Date;
  allowMissingContentType: boolean;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

interface ManifestFetchTextResult {
  text: string;
  dane?: ManifestDaneMetadata;
  warnings?: ParseWarning[];
}

interface NormalizedTlsaRecord {
  certUsage: number;
  selector: number;
  matchingType: number;
  certificateAssociationData: Buffer;
}

interface PeerCertificate {
  raw?: Buffer;
  pubkey?: Buffer;
  issuerCertificate?: PeerCertificate;
}

interface ClassifiedManifestAddress extends ManifestResolvedAddress {
  unsafeReason?: string;
}

interface ManifestSecurityValidation {
  verification: ManifestVerificationResult;
  warnings: ParseWarning[];
}

type ManifestClaimPolicy = "strict-signed" | "demo-signed" | "unsigned";
type NodeDnsPromisesWithTlsa = typeof import("node:dns/promises") & {
  resolveTlsa?: (name: string) => Promise<ManifestTlsaRecord[]>;
};

const defaultManifestHostResolver: ManifestHostResolver = async (hostname) => {
  const addresses = await lookup(hostname, { all: true, verbatim: true });
  return addresses.map(({ address, family }) => ({
    address,
    family: family === 6 ? 6 : 4,
  }));
};

const defaultManifestTlsaResolver: ManifestTlsaResolver = async (hostname, port) => {
  const builtInResolveTlsa = await loadBuiltInResolveTlsa();
  return builtInResolveTlsa(createTlsaRecordName(hostname, port));
};

async function loadBuiltInResolveTlsa(): Promise<
  (name: string) => Promise<ManifestTlsaRecord[]>
> {
  const dnsPromises = (await import("node:dns/promises")) as NodeDnsPromisesWithTlsa;

  if (typeof dnsPromises.resolveTlsa !== "function") {
    throw discoveryError(
      "RESOLVER_UNSUPPORTED",
      "Node.js 22.15 or newer is required for built-in TLSA support. Pass a custom resolveTlsa implementation or disable DANE.",
    );
  }

  return dnsPromises.resolveTlsa;
}

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
  logDebug(options.logger, "Fetching Posemesh manifest", { url }, options.redaction);

  try {
    const manifestUrl = await assertSafeManifestUrl(
      url,
      options.resolveHostname ?? defaultManifestHostResolver,
    );

    const maxBytes = options.maxBytes ?? DEFAULT_MANIFEST_MAX_BYTES;
    const fetchResult = await fetchManifestText(
      manifestUrl.url,
      manifestUrl.addresses,
      {
        timeoutMs: options.timeoutMs ?? DEFAULT_MANIFEST_TIMEOUT_MS,
        maxBytes,
        httpsRequest: options.httpsRequest ?? (request as ManifestHttpsRequest),
        allowMissingContentType: options.allowMissingContentType ?? false,
        ...(options.tlsPins ? { tlsPins: options.tlsPins } : {}),
        enableDane: options.enableDane ?? false,
        requireTlsa: options.requireTlsa ?? false,
        resolveTlsa: options.resolveTlsa ?? defaultManifestTlsaResolver,
        securityMode: options.securityMode ?? DEFAULT_MANIFEST_SECURITY_MODE,
        checkedAt: (options.now ?? (() => new Date()))(),
        ...(options.logger ? { logger: options.logger } : {}),
        ...(options.redaction ? { redaction: options.redaction } : {}),
      },
    );
    const parsed = parseFetchedManifestText(fetchResult.text, url, options);

    logInfo(
      options.logger,
      "Fetched and parsed Posemesh manifest",
      {
        url,
        verificationStatus: parsed.verification.status,
        warningCount: (fetchResult.warnings ?? []).length + (parsed.warnings ?? []).length,
      },
      options.redaction,
    );

    return {
      ...parsed,
      ...(fetchResult.dane ? { dane: fetchResult.dane } : {}),
      warnings: [...(fetchResult.warnings ?? []), ...(parsed.warnings ?? [])],
    };
  } catch (error) {
    logError(
      options.logger,
      "Posemesh manifest fetch failed",
      { url, ...errorLogFields(error, "MANIFEST_FETCH_ERROR") },
      options.redaction,
    );
    throw error;
  }
}

export function parsePosemeshManifest(
  value: unknown,
  limits: ManifestLimits = {},
): PosemeshManifest {
  const resolvedLimits = resolveManifestLimits(limits);

  if (!isRecord(value)) {
    throw new Error("Manifest must be a JSON object.");
  }

  if (value.version !== 1) {
    throw new Error("Manifest version must be 1.");
  }

  const domainManagers = parseDomainManagers(value.domainManagers, resolvedLimits);
  const relays = parseRelays(value.relays, resolvedLimits);
  const reconstructionNodes = parseServiceEndpoints<ReconstructionNode>(
    value.reconstructionNodes,
    "reconstructionNodes",
    resolvedLimits,
  );
  const splatterNodes = parseServiceEndpoints<SplatterNode>(
    value.splatterNodes,
    "splatterNodes",
    resolvedLimits,
  );
  const vlmNodes = parseVlmNodes(value.vlmNodes, resolvedLimits);
  const pathfindingServices = parseServiceEndpoints<PathfindingService>(
    value.pathfindingServices,
    "pathfindingServices",
    resolvedLimits,
  );
  const bootstrapNodes = parseBootstrapNodes(value.bootstrapNodes, resolvedLimits);
  const totalServices =
    domainManagers.length +
    relays.length +
    reconstructionNodes.length +
    splatterNodes.length +
    vlmNodes.length +
    pathfindingServices.length +
    bootstrapNodes.length;

  enforceManifestMaxCount(totalServices, resolvedLimits.maxTotalServices, "service endpoints");

  return {
    version: 1,
    ...optionalStringField(value, "name", resolvedLimits),
    ...optionalStringField(value, "sourceName", resolvedLimits),
    ...optionalUrlField(value, "manifestUrl", ["https:"], resolvedLimits),
    audience: parseAudience(value.audience, resolvedLimits),
    ...optionalStringField(value, "issuedAt", resolvedLimits),
    ...optionalStringField(value, "expiresAt", resolvedLimits),
    regions: parseStringArray(
      value.regions,
      "regions",
      manifestArrayLimit(resolvedLimits, resolvedLimits.maxRegions),
      resolvedLimits,
    ),
    domainManagers,
    relays,
    reconstructionNodes,
    splatterNodes,
    vlmNodes,
    pathfindingServices,
    bootstrapNodes,
    wallets: parseWallets(value.wallets, resolvedLimits),
    publicKeys: parsePublicKeyArray(value.publicKeys, "publicKeys", resolvedLimits),
    capabilities: parseStringArray(
      value.capabilities,
      "capabilities",
      manifestArrayLimit(resolvedLimits, resolvedLimits.maxCapabilities),
      resolvedLimits,
    ),
    ...optionalUrlField(value, "healthCheck", ["https:"], resolvedLimits),
    ...optionalStringField(value, "signature", resolvedLimits),
  };
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
  let parsed: unknown;

  try {
    parsed = JSON.parse(text) as unknown;
  } catch (error) {
    throw discoveryError(
      "MANIFEST_PARSE_ERROR",
      `Manifest response for ${originalUrl} was not valid JSON.`,
      { url: originalUrl },
      error,
    );
  }
  logDebug(
    options.logger,
    "Parsing fetched Posemesh manifest",
    { url: originalUrl, securityMode: mode },
    options.redaction,
  );

  if (mode === "strict") {
    return parseStrictFetchedManifest(text, originalUrl, options, now);
  }

  if (looksLikeSignedManifestEnvelope(parsed)) {
    try {
      return parseVerifiedFetchedManifest(text, originalUrl, options, now, mode !== "demo");
    } catch (error) {
      if (mode === "permissive") {
        const message = getErrorMessage(error, "Unknown signature error.");
        throw discoveryError(
          getErrorCode(error, "MANIFEST_SIGNATURE_INVALID"),
          `Permissive manifest verification failed for signed envelope: ${message}`,
          { url: originalUrl },
          error,
        );
      }

      return parseDemoInvalidSignedManifest(parsed, originalUrl, options, now, error);
    }
  }

  const unsignedManifest = parsePosemeshManifest(parsed, options.manifestLimits);
  const warnings = [
    createManifestWarning(
      originalUrl,
      `${mode} mode accepted an unsigned manifest. Strict mode requires a signed manifest envelope.`,
      "MANIFEST_SIGNATURE_REQUIRED",
    ),
  ];

  return createFetchedManifestResult(
    unsignedManifest,
    {
      status: "unsigned-allowed",
      verifiedAt: now.toISOString(),
    },
    originalUrl,
    options,
    now,
    "unsigned",
    warnings,
  );
}

function parseStrictFetchedManifest(
  text: string,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
): FetchedPosemeshManifest {
  const trustedKeys = options.trustedKeys ?? [];

  if (trustedKeys.length === 0) {
    throw discoveryError(
      "MANIFEST_KEY_REQUIRED",
      "Strict manifest verification requires at least one anchored or trusted key.",
      { url: manifestUrl },
    );
  }

  try {
    return parseVerifiedFetchedManifest(text, manifestUrl, options, now, true);
  } catch (error) {
    const message = getErrorMessage(error, "Unknown signature error.");
    throw discoveryError(
      getErrorCode(error, "MANIFEST_SIGNATURE_INVALID"),
      `Strict manifest verification failed: ${message}`,
      { url: manifestUrl },
      error,
    );
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
    throw discoveryError(
      "MANIFEST_KEY_REQUIRED",
      "Manifest signature verification requires at least one anchored or trusted key.",
      { url: manifestUrl },
    );
  }

  const verifiedEnvelope = verifySignedManifestEnvelopeText(text, trustedKeys, now, {
    ...(options.logger ? { logger: options.logger } : {}),
    ...(options.redaction ? { redaction: options.redaction } : {}),
  });
  const manifest = parsePosemeshManifest(
    JSON.parse(verifiedEnvelope.payloadText) as unknown,
    options.manifestLimits,
  );

  return createFetchedManifestResult(
    manifest,
    verifiedEnvelope.verification,
    manifestUrl,
    options,
    now,
    requireSignedClaims ? "strict-signed" : "demo-signed",
  );
}

function parseDemoInvalidSignedManifest(
  parsed: unknown,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  verificationError: unknown,
): FetchedPosemeshManifest {
  const payloadText = decodeEnvelopePayloadText(parsed);
  const manifest = parsePosemeshManifest(JSON.parse(payloadText) as unknown, options.manifestLimits);
  const envelopeMetadata = readEnvelopeMetadata(parsed);
  const message =
    verificationError instanceof Error ? verificationError.message : "Unknown signature error.";

  return createFetchedManifestResult(
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
    "demo-signed",
    [
      createManifestWarning(
        manifestUrl,
        `demo mode accepted a manifest with invalid signature verification: ${message}`,
        getErrorCode(verificationError, "MANIFEST_SIGNATURE_INVALID"),
      ),
    ],
  );
}

function createFetchedManifestResult(
  manifest: PosemeshManifest,
  verification: ManifestVerificationResult,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  claimPolicy: ManifestClaimPolicy,
  warnings: ParseWarning[] = [],
): FetchedPosemeshManifest {
  const security = validateManifestSecurityClaims(
    manifest,
    verification,
    manifestUrl,
    options,
    now,
    claimPolicy,
  );
  const allWarnings = [...warnings, ...security.warnings];

  return {
    manifest,
    verification: security.verification,
    cache: createManifestCacheMetadata(manifest, now, options),
    ...(allWarnings.length > 0 ? { warnings: allWarnings } : {}),
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

function createManifestWarning(
  url: string,
  message: string,
  code?: DiscoveryErrorCode,
): ParseWarning {
  return createWarning({
    source: "manifest",
    url,
    ...(code ? { code } : {}),
    message,
  });
}

function validateManifestSecurityClaims(
  manifest: PosemeshManifest,
  verification: ManifestVerificationResult,
  manifestUrl: string,
  options: FetchPosemeshManifestOptions,
  now: Date,
  claimPolicy: ManifestClaimPolicy,
): ManifestSecurityValidation {
  const warnings: ParseWarning[] = [];
  const requireSignedClaims = claimPolicy === "strict-signed";
  const warnRelaxedSignedClaims = claimPolicy === "demo-signed";

  validateExpectedName(manifest, options.expectedName);
  warnings.push(
    ...validateExpectedManifestUrl(
      manifest,
      options.expectedManifestUrl ?? manifestUrl,
      requireSignedClaims,
      warnRelaxedSignedClaims,
    ),
  );
  warnings.push(
    ...validateExpectedAudience(
      manifest,
      options.expectedAudience,
      requireSignedClaims,
      warnRelaxedSignedClaims,
      manifestUrl,
    ),
  );

  const issuedAt = validateManifestTimestamp(manifest.issuedAt, "issuedAt", requireSignedClaims);
  const expiresAt = validateManifestTimestamp(manifest.expiresAt, "expiresAt", requireSignedClaims);

  if (warnRelaxedSignedClaims) {
    if (!manifest.issuedAt) {
      warnings.push(
        createManifestWarning(
          manifestUrl,
          "demo mode accepted a signed manifest payload without issuedAt.",
          "MANIFEST_REPLAY_INVALID",
        ),
      );
    }

    if (!manifest.expiresAt) {
      warnings.push(
        createManifestWarning(
          manifestUrl,
          "demo mode accepted a signed manifest payload without expiresAt.",
          "MANIFEST_REPLAY_INVALID",
        ),
      );
    }
  }

  if (issuedAt && expiresAt) {
    validateManifestFreshness(issuedAt, expiresAt, now, options);
  }

  return {
    verification: {
      ...verification,
      ...(manifest.issuedAt ? { issuedAt: manifest.issuedAt } : {}),
      ...(manifest.expiresAt ? { expiresAt: manifest.expiresAt } : {}),
    },
    warnings,
  };
}

function parseDomainManagers(
  value: unknown,
  limits: ResolvedManifestLimits,
): DomainManager[] {
  return parseObjectArray(
    value,
    "domainManagers",
    manifestArrayLimit(limits, limits.maxServicesPerCategory),
  ).map((item) => {
    return {
      ...parseServiceEndpoint<DomainManager>(item, "domainManagers", limits),
      ...optionalStringField(item, "wallet", limits),
    };
  });
}

function parseRelays(value: unknown, limits: ResolvedManifestLimits): Relay[] {
  return parseObjectArray(value, "relays", manifestArrayLimit(limits, limits.maxServicesPerCategory)).map((item) => {
    return {
      ...parseServiceEndpoint<Relay>(item, "relays", limits),
      ...optionalStringField(item, "sessionPolicy", limits),
    };
  });
}

function parseBootstrapNodes(
  value: unknown,
  limits: ResolvedManifestLimits,
): BootstrapNode[] {
  return parseServiceEndpoints<BootstrapNode>(value, "bootstrapNodes", limits);
}

function parseVlmNodes(value: unknown, limits: ResolvedManifestLimits): VlmNode[] {
  return parseObjectArray(value, "vlmNodes", manifestArrayLimit(limits, limits.maxServicesPerCategory)).map((item) => {
    const models = parseStringArray(
      item.models,
      "vlmNodes.models",
      manifestArrayLimit(limits, limits.maxModels),
      limits,
    );

    return {
      ...parseServiceEndpoint<VlmNode>(item, "vlmNodes", limits),
      ...(models.length > 0 ? { models } : {}),
    };
  });
}

function parseServiceEndpoints<T extends PosemeshServiceEndpoint>(
  value: unknown,
  field: string,
  limits: ResolvedManifestLimits,
): T[] {
  return parseObjectArray(value, field, manifestArrayLimit(limits, limits.maxServicesPerCategory)).map((item) =>
    parseServiceEndpoint<T>(item, field, limits),
  );
}

function parseServiceEndpoint<T extends PosemeshServiceEndpoint>(
  value: Record<string, unknown>,
  field: string,
  limits: ResolvedManifestLimits,
): T {
  const endpoint: PosemeshServiceEndpoint = {
    ...optionalStringField(value, "id", limits),
    ...optionalStringField(value, "name", limits),
    endpoint: requiredUrlField(value, "endpoint", field, ["https:", "wss:"], limits),
    ...optionalStringField(value, "region", limits),
    ...optionalStringField(value, "transport", limits),
    ...optionalPublicKeyField(value, "publicKey", limits),
    capabilities: parseStringArray(
      value.capabilities,
      `${field}.capabilities`,
      manifestArrayLimit(limits, limits.maxCapabilities),
      limits,
    ),
    ...optionalUrlField(value, "healthCheck", ["https:"], limits),
  };

  return endpoint as T;
}

function parseWallets(value: unknown, limits: ResolvedManifestLimits): WalletReference[] {
  return parseObjectArray(value, "wallets", manifestArrayLimit(limits, limits.maxWallets)).map((item) => ({
    address: requiredStringField(item, "address", "wallets", limits),
    ...optionalStringField(item, "chain", limits),
    ...optionalStringField(item, "role", limits),
    ...optionalPublicKeyField(item, "publicKey", limits),
  }));
}

function parseObjectArray(
  value: unknown,
  field: string,
  maxItems: number,
): Record<string, unknown>[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`Manifest field ${field} must be an array.`);
  }

  enforceManifestMaxCount(value.length, maxItems, `Manifest field ${field}`);

  return value.map((item, index) => {
    if (!isRecord(item)) {
      throw new Error(`Manifest field ${field}[${index}] must be an object.`);
    }

    return item;
  });
}

function parseStringArray(
  value: unknown,
  field: string,
  maxItems: number,
  limits: ResolvedManifestLimits,
): string[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error("Manifest string list must be an array.");
  }

  enforceManifestMaxCount(value.length, maxItems, `Manifest field ${field}`);

  return value.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(
        `Manifest string list item ${index} (${field}[${index}]) must be a non-empty string.`,
      );
    }

    const trimmed = item.trim();
    enforceManifestMaxBytes(
      trimmed,
      limits.maxStringBytes,
      `Manifest field ${field}[${index}]`,
    );
    return trimmed;
  });
}

function parseAudience(value: unknown, limits: ResolvedManifestLimits): string[] {
  if (value === undefined) {
    return [];
  }

  if (typeof value === "string") {
    if (!value.trim()) {
      throw new Error("Manifest audience must be a non-empty string or string array.");
    }

    const trimmed = value.trim();
    enforceManifestMaxBytes(trimmed, limits.maxStringBytes, "Manifest field audience");
    return [trimmed];
  }

  return parseStringArray(value, "audience", manifestArrayLimit(limits, limits.maxAudience), limits);
}

function parsePublicKeyArray(
  value: unknown,
  field: string,
  limits: ResolvedManifestLimits,
): string[] {
  return parseStringArray(value, field, manifestArrayLimit(limits, limits.maxPublicKeys), limits).map((item, index) =>
    parsePublicKey(item, `Manifest field ${field}[${index}]`),
  );
}

function requiredStringField(
  value: Record<string, unknown>,
  field: string,
  parent: string,
  limits: ResolvedManifestLimits,
): string {
  const item = value[field];

  if (typeof item !== "string" || !item.trim()) {
    throw new Error(`Manifest field ${parent}.${field} is required.`);
  }

  const trimmed = item.trim();
  enforceManifestMaxBytes(trimmed, limits.maxStringBytes, `Manifest field ${parent}.${field}`);
  return trimmed;
}

function requiredUrlField(
  value: Record<string, unknown>,
  field: string,
  parent: string,
  protocols: string[],
  limits: ResolvedManifestLimits,
): string {
  return validateUrl(
    requiredStringField(value, field, parent, limits),
    `${parent}.${field}`,
    protocols,
    limits,
  );
}

function optionalStringField<T extends string>(
  value: Record<string, unknown>,
  field: T,
  limits: ResolvedManifestLimits,
): Partial<Record<T, string>> {
  const item = value[field];

  if (item === undefined) {
    return {};
  }

  if (typeof item !== "string" || !item.trim()) {
    throw new Error(`Manifest field ${field} must be a non-empty string.`);
  }

  const trimmed = item.trim();
  enforceManifestMaxBytes(trimmed, limits.maxStringBytes, `Manifest field ${field}`);
  return { [field]: trimmed } as Partial<Record<T, string>>;
}

function optionalPublicKeyField<T extends string>(
  value: Record<string, unknown>,
  field: T,
  limits: ResolvedManifestLimits,
): Partial<Record<T, string>> {
  const stringField = optionalStringField(value, field, limits);
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
  limits: ResolvedManifestLimits,
): Partial<Record<T, string>> {
  const stringField = optionalStringField(value, field, limits);
  const item = stringField[field];

  if (!item) {
    return {};
  }

  return {
    [field]: validateUrl(item, field, protocols, limits),
  } as Partial<Record<T, string>>;
}

function validateExpectedName(manifest: PosemeshManifest, expectedName: string | undefined): void {
  if (!expectedName) {
    return;
  }

  if (!manifest.sourceName) {
    throw discoveryError(
      "MANIFEST_BINDING_MISMATCH",
      `Manifest sourceName is required and must match requested name ${expectedName}.`,
      { expectedName },
    );
  }

  if (normalizeDiscoveryNameForBinding(manifest.sourceName) !== normalizeDiscoveryNameForBinding(expectedName)) {
    throw discoveryError(
      "MANIFEST_BINDING_MISMATCH",
      `Manifest sourceName ${manifest.sourceName} does not match requested name ${expectedName}.`,
      { expectedName, sourceName: manifest.sourceName },
    );
  }
}

function validateExpectedManifestUrl(
  manifest: PosemeshManifest,
  expectedManifestUrl: string | undefined,
  requireManifestUrl: boolean,
  warnMissingManifestUrl: boolean,
): ParseWarning[] {
  if (!expectedManifestUrl) {
    return [];
  }

  if (!manifest.manifestUrl) {
    if (requireManifestUrl) {
      throw discoveryError(
        "MANIFEST_BINDING_MISMATCH",
        "Signed manifest payload must include manifestUrl.",
        { expectedManifestUrl },
      );
    }

    if (warnMissingManifestUrl) {
      return [
        createManifestWarning(
          expectedManifestUrl,
          "demo mode accepted a signed manifest payload without manifestUrl.",
          "MANIFEST_BINDING_MISMATCH",
        ),
      ];
    }

    return [];
  }

  if (normalizeUrlString(manifest.manifestUrl) !== normalizeUrlString(expectedManifestUrl)) {
    throw discoveryError(
      "MANIFEST_BINDING_MISMATCH",
      `Manifest manifestUrl ${manifest.manifestUrl} does not match requested URL ${expectedManifestUrl}.`,
      { expectedManifestUrl, manifestUrl: manifest.manifestUrl },
    );
  }

  return [];
}

function validateExpectedAudience(
  manifest: PosemeshManifest,
  expectedAudience: string | string[] | undefined,
  requireAudience: boolean,
  warnMissingAudience: boolean,
  manifestUrl: string,
): ParseWarning[] {
  const expectedAudiences = normalizeExpectedAudiences(expectedAudience);

  if (expectedAudiences.length === 0) {
    return [];
  }

  const manifestAudiences = (manifest.audience ?? []).map(normalizeAudienceForBinding);

  if (manifestAudiences.length === 0) {
    if (requireAudience) {
      throw discoveryError(
        "MANIFEST_BINDING_MISMATCH",
        "Signed manifest payload must include audience.",
        { expectedAudience: expectedAudiences.join(",") },
      );
    }

    return warnMissingAudience
      ? [
          createManifestWarning(
            manifestUrl,
            "demo mode accepted a signed manifest payload without audience.",
            "MANIFEST_BINDING_MISMATCH",
          ),
        ]
      : [];
  }

  const matched = expectedAudiences.some((audience) => manifestAudiences.includes(audience));

  if (!matched) {
    throw discoveryError(
      "MANIFEST_BINDING_MISMATCH",
      `Manifest audience ${manifest.audience?.join(", ") ?? "(empty)"} does not match expected audience ${expectedAudiences.join(", ")}.`,
      {
        expectedAudience: expectedAudiences.join(","),
        manifestAudience: manifest.audience?.join(",") ?? "",
      },
    );
  }

  return [];
}

function validateManifestTimestamp(
  value: string | undefined,
  field: "issuedAt" | "expiresAt",
  required: boolean,
): Date | undefined {
  if (!value) {
    if (required) {
      throw discoveryError(
        "MANIFEST_REPLAY_INVALID",
        `Signed manifest payload must include ${field}.`,
        { field },
      );
    }

    return undefined;
  }

  const parsed = new Date(value);

  if (!Number.isFinite(parsed.getTime()) || parsed.toISOString() !== value) {
    throw discoveryError(
      "MANIFEST_REPLAY_INVALID",
      `Manifest ${field} must be a valid ISO-8601 UTC timestamp.`,
      { field },
    );
  }

  return parsed;
}

function validateManifestFreshness(
  issuedAt: Date,
  expiresAt: Date,
  now: Date,
  options: FetchPosemeshManifestOptions,
): void {
  const maxClockSkewMs = readNonNegativeMillisecondsOption(
    options.maxClockSkewMs ?? DEFAULT_MANIFEST_MAX_CLOCK_SKEW_MS,
    "maxClockSkewMs",
  );
  const maxManifestTtlMs = readNonNegativeMillisecondsOption(
    options.maxManifestTtlMs ?? DEFAULT_MANIFEST_MAX_TTL_MS,
    "maxManifestTtlMs",
  );
  const maxManifestAgeMs = readOptionalNonNegativeMillisecondsOption(
    options.maxManifestAgeMs,
    "maxManifestAgeMs",
  );
  const ttlMs = expiresAt.getTime() - issuedAt.getTime();
  const ageMs = now.getTime() - issuedAt.getTime();

  if (ttlMs <= 0) {
    throw discoveryError("MANIFEST_REPLAY_INVALID", "Manifest expiresAt must be after issuedAt.");
  }

  if (ttlMs > maxManifestTtlMs) {
    throw discoveryError(
      "MANIFEST_REPLAY_INVALID",
      `Manifest validity window must not exceed ${maxManifestTtlMs}ms.`,
      { maxManifestTtlMs },
    );
  }

  if (issuedAt.getTime() - maxClockSkewMs > now.getTime()) {
    throw discoveryError("MANIFEST_REPLAY_INVALID", "Manifest is not valid yet.");
  }

  if (maxManifestAgeMs !== undefined && ageMs > maxManifestAgeMs) {
    throw discoveryError(
      "MANIFEST_REPLAY_INVALID",
      `Manifest age must not exceed ${maxManifestAgeMs}ms.`,
      { maxManifestAgeMs },
    );
  }

  if (expiresAt.getTime() + maxClockSkewMs < now.getTime()) {
    throw discoveryError("MANIFEST_REPLAY_INVALID", "Manifest has expired.");
  }
}

function createManifestCacheMetadata(
  manifest: PosemeshManifest,
  now: Date,
  options: FetchPosemeshManifestOptions,
): ManifestCacheMetadata {
  const issuedAt = parseCacheTimestamp(manifest.issuedAt);
  const expiresAt = parseCacheTimestamp(manifest.expiresAt);
  const maxManifestAgeMs = readOptionalNonNegativeMillisecondsOption(
    options.maxManifestAgeMs,
    "maxManifestAgeMs",
  );
  const ageMs = issuedAt ? Math.max(0, now.getTime() - issuedAt.getTime()) : undefined;
  const base = {
    checkedAt: now.toISOString(),
    ...(manifest.issuedAt ? { issuedAt: manifest.issuedAt } : {}),
    ...(manifest.expiresAt ? { expiresAt: manifest.expiresAt } : {}),
    ...(ageMs !== undefined ? { ageMs } : {}),
    ...(maxManifestAgeMs !== undefined ? { maxManifestAgeMs } : {}),
  };

  if (!expiresAt) {
    return {
      cacheStatus: "uncacheable",
      ...base,
      reason: "Manifest does not include expiresAt.",
    };
  }

  if (expiresAt.getTime() <= now.getTime()) {
    return {
      cacheStatus: "stale",
      ...base,
      reason: "Manifest expiresAt is not in the future.",
    };
  }

  if (maxManifestAgeMs !== undefined && ageMs !== undefined && ageMs > maxManifestAgeMs) {
    return {
      cacheStatus: "stale",
      ...base,
      reason: "Manifest age exceeds maxManifestAgeMs.",
    };
  }

  return {
    cacheStatus: "fresh",
    ...base,
  };
}

function parseCacheTimestamp(value: string | undefined): Date | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = new Date(value);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === value ? parsed : undefined;
}

function readNonNegativeMillisecondsOption(value: number, field: string): number {
  if (!Number.isFinite(value) || value < 0) {
    throw new Error(`${field} must be a non-negative finite number.`);
  }

  return value;
}

function readOptionalNonNegativeMillisecondsOption(
  value: number | undefined,
  field: string,
): number | undefined {
  if (value === undefined) {
    return undefined;
  }

  return readNonNegativeMillisecondsOption(value, field);
}

function resolveManifestLimits(limits: ManifestLimits): ResolvedManifestLimits {
  return {
    maxStringBytes: readPositiveIntegerLimit(
      limits.maxStringBytes,
      DEFAULT_MANIFEST_LIMITS.maxStringBytes,
      "maxStringBytes",
    ),
    maxUrlBytes: readPositiveIntegerLimit(
      limits.maxUrlBytes,
      DEFAULT_MANIFEST_LIMITS.maxUrlBytes,
      "maxUrlBytes",
    ),
    maxArrayItems: readPositiveIntegerLimit(
      limits.maxArrayItems,
      DEFAULT_MANIFEST_LIMITS.maxArrayItems,
      "maxArrayItems",
    ),
    maxCapabilities: readPositiveIntegerLimit(
      limits.maxCapabilities,
      DEFAULT_MANIFEST_LIMITS.maxCapabilities,
      "maxCapabilities",
    ),
    maxPublicKeys: readPositiveIntegerLimit(
      limits.maxPublicKeys,
      DEFAULT_MANIFEST_LIMITS.maxPublicKeys,
      "maxPublicKeys",
    ),
    maxServicesPerCategory: readPositiveIntegerLimit(
      limits.maxServicesPerCategory,
      DEFAULT_MANIFEST_LIMITS.maxServicesPerCategory,
      "maxServicesPerCategory",
    ),
    maxTotalServices: readPositiveIntegerLimit(
      limits.maxTotalServices,
      DEFAULT_MANIFEST_LIMITS.maxTotalServices,
      "maxTotalServices",
    ),
    maxWallets: readPositiveIntegerLimit(
      limits.maxWallets,
      DEFAULT_MANIFEST_LIMITS.maxWallets,
      "maxWallets",
    ),
    maxRegions: readPositiveIntegerLimit(
      limits.maxRegions,
      DEFAULT_MANIFEST_LIMITS.maxRegions,
      "maxRegions",
    ),
    maxAudience: readPositiveIntegerLimit(
      limits.maxAudience,
      DEFAULT_MANIFEST_LIMITS.maxAudience,
      "maxAudience",
    ),
    maxModels: readPositiveIntegerLimit(
      limits.maxModels,
      DEFAULT_MANIFEST_LIMITS.maxModels,
      "maxModels",
    ),
  };
}

function readPositiveIntegerLimit(
  value: number | undefined,
  fallback: number,
  field: string,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`Manifest limit ${field} must be a positive integer.`);
  }

  return value;
}

function enforceManifestMaxCount(count: number, max: number, field: string): void {
  if (count > max) {
    throw new Error(`${field} exceeds limit ${max}.`);
  }
}

function enforceManifestMaxBytes(value: string, max: number, field: string): void {
  const bytes = Buffer.byteLength(value, "utf8");

  if (bytes > max) {
    throw new Error(`${field} exceeds ${max} bytes.`);
  }
}

function manifestArrayLimit(limits: ResolvedManifestLimits, specificLimit: number): number {
  return Math.min(limits.maxArrayItems, specificLimit);
}

function normalizeUrlString(value: string): string {
  const parsed = new URL(value);

  parsed.protocol = parsed.protocol.toLowerCase();
  parsed.hostname = normalizeHost(parsed.hostname);

  if (parsed.protocol === "https:" && parsed.port === "443") {
    parsed.port = "";
  }

  return parsed.toString();
}

function normalizeDiscoveryNameForBinding(value: string): string {
  return normalizeName(value).toLowerCase();
}

function normalizeExpectedAudiences(value: string | string[] | undefined): string[] {
  if (value === undefined) {
    return [];
  }

  const values = Array.isArray(value) ? value : [value];
  return values.map(normalizeAudienceForBinding).filter(Boolean);
}

function normalizeAudienceForBinding(value: string): string {
  return normalizeName(value).toLowerCase();
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
    throw discoveryError("MANIFEST_URL_INVALID", `Manifest URL is invalid: ${url}`, { url });
  }

  if (!isAllowedProtocol(parsed.protocol, ["https:"])) {
    throw discoveryError(
      "MANIFEST_URL_INVALID",
      "Manifest URL must use https.",
      { url, protocol: parsed.protocol },
    );
  }

  const addresses = await assertPublicManifestHost(parsed.hostname, resolveHostname);
  return { url: parsed, addresses };
}

function validateUrl(
  url: string,
  field: string,
  protocols: string[],
  limits: ResolvedManifestLimits,
): string {
  enforceManifestMaxBytes(url, limits.maxUrlBytes, `Manifest field ${field}`);
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
  const unsafeLiteralReason = getUnsafeManifestHostReason(host);

  if (unsafeLiteralReason) {
    throw discoveryError(
      "MANIFEST_URL_UNSAFE",
      `Manifest URL must not use localhost, private, or reserved network addresses (${unsafeLiteralReason}).`,
      { hostname: host, reason: unsafeLiteralReason },
    );
  }

  const ipVersion = isIP(host);

  if (ipVersion) {
    return [{ address: host, family: ipVersion === 6 ? 6 : 4 }];
  }

  let addresses: Awaited<ReturnType<ManifestHostResolver>>;

  try {
    addresses = await resolveHostname(host);
  } catch (error) {
    const message = getErrorMessage(error, "Unknown host lookup error.");
    throw discoveryError(
      "MANIFEST_URL_UNSAFE",
      `Manifest host lookup failed for ${host}: ${message}`,
      { hostname: host },
      error,
    );
  }

  if (addresses.length === 0) {
    throw discoveryError(
      "MANIFEST_URL_UNSAFE",
      `Manifest host lookup returned no addresses for ${host}.`,
      { hostname: host },
    );
  }

  const normalizedAddresses: ClassifiedManifestAddress[] = addresses.map(({ address }) => {
    const normalizedAddress = normalizeHost(address);
    const resolvedFamily = isIP(normalizedAddress);

    if (!resolvedFamily) {
      throw discoveryError(
        "MANIFEST_URL_UNSAFE",
        `Manifest host ${host} resolves to an invalid IP address.`,
        { hostname: host, address },
      );
    }

    const unsafeReason = getUnsafeManifestHostReason(normalizedAddress);

    return {
      address: normalizedAddress,
      family: resolvedFamily === 6 ? 6 : 4,
      ...(unsafeReason ? { unsafeReason } : {}),
    } satisfies ClassifiedManifestAddress;
  });

  const blockedAddresses = normalizedAddresses.filter(({ unsafeReason }) => unsafeReason);
  const publicAddresses = normalizedAddresses.filter(({ unsafeReason }) => !unsafeReason);

  if (blockedAddresses.length > 0) {
    const blockedSummary = blockedAddresses
      .map(({ address, unsafeReason }) => `${address} (${unsafeReason ?? "non-public"})`)
      .join(", ");

    if (publicAddresses.length > 0) {
      throw discoveryError(
        "MANIFEST_URL_UNSAFE",
        `Manifest host ${host} resolves to mixed public/private or reserved network addresses: ${blockedSummary}.`,
        { hostname: host, blockedAddresses: blockedSummary },
      );
    }

    throw discoveryError(
      "MANIFEST_URL_UNSAFE",
      `Manifest host ${host} resolves to localhost, private, or reserved network addresses: ${blockedSummary}.`,
      { hostname: host, blockedAddresses: blockedSummary },
    );
  }

  return normalizedAddresses;
}

function normalizeHost(hostname: string): string {
  return hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
}

function isLocalOrPrivateHost(hostname: string): boolean {
  return getUnsafeManifestHostReason(hostname) !== undefined;
}

function getUnsafeManifestHostReason(hostname: string): string | undefined {
  const host = normalizeHost(hostname);

  if (host === "localhost" || host.endsWith(".localhost")) {
    return "localhost hostname";
  }

  const ipVersion = isIP(host);

  if (ipVersion === 4) {
    return isPrivateIpv4(host) ? "non-public IPv4 address" : undefined;
  }

  if (ipVersion === 6) {
    const mappedIpv4 = parseIpv4MappedIpv6(host);

    if (mappedIpv4) {
      return `IPv4-mapped IPv6 address ${mappedIpv4}`;
    }

    return isPrivateIpv6(host) ? "non-public IPv6 address" : undefined;
  }

  return undefined;
}

const BLOCKED_IPV4_RANGES: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

const BLOCKED_IPV6_RANGES: Array<[string, number]> = [
  ["::", 96],
  ["::", 128],
  ["::1", 128],
  ["::ffff:0:0", 96],
  ["64:ff9b::", 96],
  ["64:ff9b:1::", 48],
  ["100::", 64],
  ["2001::", 32],
  ["2001:2::", 48],
  ["2001:10::", 28],
  ["2001:20::", 28],
  ["2001:db8::", 32],
  ["2002::", 16],
  ["3fff::", 20],
  ["fc00::", 7],
  ["fe80::", 10],
  ["ff00::", 8],
];

function isPrivateIpv4(host: string): boolean {
  return BLOCKED_IPV4_RANGES.some(([base, prefixLength]) =>
    isIpv4InRange(host, base, prefixLength),
  );
}

function isPrivateIpv6(host: string): boolean {
  const mappedIpv4 = parseIpv4MappedIpv6(host);

  if (mappedIpv4) {
    return true;
  }

  return BLOCKED_IPV6_RANGES.some(([base, prefixLength]) =>
    isIpv6InRange(host, base, prefixLength),
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

function isIpv4InRange(host: string, base: string, prefixLength: number): boolean {
  const hostValue = ipv4ToNumber(host);
  const baseValue = ipv4ToNumber(base);
  const mask = prefixLength === 0 ? 0 : (0xffffffff << (32 - prefixLength)) >>> 0;

  return (hostValue & mask) === (baseValue & mask);
}

function ipv4ToNumber(host: string): number {
  return host.split(".").reduce((value, part) => (value << 8) + Number(part), 0) >>> 0;
}

function isIpv6InRange(host: string, base: string, prefixLength: number): boolean {
  const hostValue = ipv6ToBigInt(host);
  const baseValue = ipv6ToBigInt(base);
  const shift = BigInt(128 - prefixLength);

  return (hostValue >> shift) === (baseValue >> shift);
}

function ipv6ToBigInt(host: string): bigint {
  const expanded = expandIpv6Address(host);

  return expanded.reduce((value, part) => (value << 16n) + BigInt(part), 0n);
}

function expandIpv6Address(host: string): number[] {
  const normalized = normalizeEmbeddedIpv4InIpv6(host);
  const [head = "", tail = "", extra] = normalized.split("::");

  if (extra !== undefined) {
    throw new Error(`Invalid IPv6 address: ${host}`);
  }

  const headParts = splitIpv6Parts(head);
  const tailParts = splitIpv6Parts(tail);
  const zeroCount = 8 - headParts.length - tailParts.length;

  if (zeroCount < 0 || (normalized.includes("::") && zeroCount < 1)) {
    throw new Error(`Invalid IPv6 address: ${host}`);
  }

  const zeroParts = Array.from({ length: normalized.includes("::") ? zeroCount : 0 }, () => 0);
  const parts = [...headParts, ...zeroParts, ...tailParts];

  if (parts.length !== 8) {
    throw new Error(`Invalid IPv6 address: ${host}`);
  }

  return parts;
}

function normalizeEmbeddedIpv4InIpv6(host: string): string {
  if (!host.includes(".")) {
    return host;
  }

  const lastColon = host.lastIndexOf(":");
  const ipv4 = host.slice(lastColon + 1);

  if (isIP(ipv4) !== 4) {
    return host;
  }

  const octets = ipv4.split(".").map((part) => Number(part)) as [
    number,
    number,
    number,
    number,
  ];
  const high = (octets[0] << 8) + octets[1];
  const low = (octets[2] << 8) + octets[3];

  return `${host.slice(0, lastColon)}:${high.toString(16)}:${low.toString(16)}`;
}

function splitIpv6Parts(value: string): number[] {
  if (!value) {
    return [];
  }

  return value.split(":").map((part) => {
    const parsed = Number.parseInt(part, 16);

    if (!Number.isFinite(parsed) || parsed < 0 || parsed > 0xffff) {
      throw new Error(`Invalid IPv6 segment: ${part}`);
    }

    return parsed;
  });
}

function fetchManifestText(
  url: URL,
  addresses: ManifestResolvedAddress[],
  policy: ManifestFetchPolicy,
): Promise<ManifestFetchTextResult> {
  return tryManifestAddresses(url, addresses, policy);
}

async function tryManifestAddresses(
  url: URL,
  addresses: ManifestResolvedAddress[],
  policy: ManifestFetchPolicy,
): Promise<ManifestFetchTextResult> {
  // Try resolved addresses one at a time so a dead address does not fail the whole manifest.
  const errors: string[] = [];

  for (const address of addresses) {
    try {
      logDebug(
        policy.logger,
        "Trying manifest address",
        { url: url.toString(), address: address.address, family: address.family },
        policy.redaction,
      );
      return await fetchManifestTextFromAddress(url, address, policy);
    } catch (error) {
      const message = getErrorMessage(error, "Unknown manifest fetch error.");
      logWarn(
        policy.logger,
        "Manifest address fetch failed",
        {
          url: url.toString(),
          address: address.address,
          ...errorLogFields(error, "MANIFEST_FETCH_ERROR"),
        },
        policy.redaction,
      );
      errors.push(`${address.address}: ${message}`);
    }
  }

  throw discoveryError(
    "MANIFEST_FETCH_ERROR",
    `Manifest fetch failed for ${url.toString()} using ${addresses.length} resolved address(es): ${errors.join("; ")}`,
    { url: url.toString(), addressCount: addresses.length },
  );
}

function fetchManifestTextFromAddress(
  url: URL,
  address: ManifestResolvedAddress,
  policy: ManifestFetchPolicy,
): Promise<ManifestFetchTextResult> {
  return new Promise((resolve, reject) => {
    const chunks: Uint8Array[] = [];
    const decoder = new TextDecoder();
    let bytesRead = 0;
    let dane: ManifestDaneMetadata | undefined;
    let daneWarnings: ParseWarning[] = [];

    const req = policy.httpsRequest(
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
      async (response) => {
        const statusCode = response.statusCode ?? 0;

        if (statusCode >= 300 && statusCode < 400) {
          response.resume();
          reject(
            discoveryError(
              "MANIFEST_REDIRECT_REJECTED",
              `Manifest fetch failed for ${url.toString()}: redirects are not allowed.`,
              { url: url.toString(), statusCode },
            ),
          );
          return;
        }

        if (statusCode < 200 || statusCode >= 300) {
          response.resume();
          reject(
            discoveryError(
              "MANIFEST_HTTP_ERROR",
              `Manifest fetch failed for ${url.toString()}: HTTP ${statusCode}`,
              { url: url.toString(), statusCode },
            ),
          );
          return;
        }

        try {
          assertTlsSpkiPin(url, response, policy.tlsPins);
          const daneResult = await validateManifestDane(url, response, policy);
          dane = daneResult.dane;
          daneWarnings = daneResult.warnings;
        } catch (error) {
          response.resume();
          reject(error);
          return;
        }

        const contentType = response.headers["content-type"];
        const declaredContentType = Array.isArray(contentType) ? contentType[0] : contentType;

        if (!isAllowedJsonContentType(declaredContentType, policy.allowMissingContentType)) {
          response.resume();
          reject(
            discoveryError(
              "MANIFEST_CONTENT_TYPE_INVALID",
              `Manifest response for ${url.toString()} must use Content-Type application/json.`,
              { url: url.toString(), contentType: declaredContentType ?? "" },
            ),
          );
          return;
        }

        const contentLength = response.headers["content-length"];
        const declaredLength = Array.isArray(contentLength) ? contentLength[0] : contentLength;

        if (declaredLength && Number(declaredLength) > policy.maxBytes) {
          response.resume();
          reject(
            discoveryError(
              "MANIFEST_TOO_LARGE",
              `Manifest response is larger than ${policy.maxBytes} bytes.`,
              { url: url.toString(), maxBytes: policy.maxBytes },
            ),
          );
          return;
        }

        response.on("data", (chunk: Uint8Array) => {
          bytesRead += chunk.byteLength;

          if (bytesRead > policy.maxBytes) {
            req.destroy(
              discoveryError(
                "MANIFEST_TOO_LARGE",
                `Manifest response is larger than ${policy.maxBytes} bytes.`,
                { url: url.toString(), maxBytes: policy.maxBytes },
              ),
            );
            return;
          }

          chunks.push(chunk);
        });

        response.on("end", () => {
          resolve({
            text: decoder.decode(Buffer.concat(chunks)),
            ...(dane ? { dane } : {}),
            ...(daneWarnings.length > 0 ? { warnings: daneWarnings } : {}),
          });
        });

        response.on("error", reject);
      },
    );

    req.setTimeout(policy.timeoutMs, () => {
      req.destroy(
        discoveryError(
          "MANIFEST_TIMEOUT",
          `Manifest fetch timed out after ${policy.timeoutMs}ms.`,
          { url: url.toString(), timeoutMs: policy.timeoutMs },
        ),
      );
    });

    req.on("error", reject);
    req.end();
  });
}

function assertTlsSpkiPin(
  url: URL,
  response: { socket?: unknown },
  tlsPins: Record<string, string[]> | undefined,
): void {
  const pins = findTlsPinsForHostname(url.hostname, tlsPins);

  if (pins.length === 0) {
    return;
  }

  const actualPin = readResponseSpkiSha256(response);
  const normalizedPins = pins.map(normalizeSpkiPin);

  if (!normalizedPins.includes(actualPin)) {
    throw discoveryError(
      "MANIFEST_TLS_PIN_MISMATCH",
      `TLS SPKI pin mismatch for ${normalizeHost(url.hostname)}.`,
      { hostname: normalizeHost(url.hostname) },
    );
  }
}

async function validateManifestDane(
  url: URL,
  response: { socket?: unknown },
  policy: ManifestFetchPolicy,
): Promise<{ dane?: ManifestDaneMetadata; warnings: ParseWarning[] }> {
  if (!policy.enableDane && !policy.requireTlsa) {
    return { warnings: [] };
  }

  const host = normalizeHost(url.hostname);
  const port = Number(url.port || 443);
  const recordName = createTlsaRecordName(host, port);
  const base = {
    checkedAt: policy.checkedAt.toISOString(),
    host,
    port,
    recordName,
  };
  let records: ManifestTlsaRecord[];

  try {
    records = await policy.resolveTlsa(host, port);
  } catch (error) {
    if (isDnsNoRecordsError(error)) {
      return handleMissingTlsaRecords(url, policy, {
        ...base,
        status: "no-records",
        recordCount: 0,
      });
    }

    const message = getErrorMessage(error, "Unknown TLSA lookup error.");
    const dane = {
      ...base,
      status: "failed" as const,
      recordCount: 0,
      error: `TLSA lookup failed: ${message}`,
    };

    if (policy.requireTlsa) {
      throw discoveryError(
        "DANE_TLSA_LOOKUP_ERROR",
        dane.error,
        { host, port, recordName },
        error,
      );
    }

    return {
      dane,
      warnings: [
        createManifestWarning(
          url.toString(),
          `${dane.error}; falling back to normal TLS validation.`,
          "DANE_TLSA_LOOKUP_ERROR",
        ),
      ],
    };
  }

  if (records.length === 0) {
    return handleMissingTlsaRecords(url, policy, {
      ...base,
      status: "no-records",
      recordCount: 0,
    });
  }

  const normalizedRecords = records.map(normalizeTlsaRecord);
  const peerCertificates = readPeerCertificateChain(response);
  const matchedRecord = findMatchingTlsaRecord(normalizedRecords, peerCertificates);

  if (!matchedRecord) {
    const dane = {
      ...base,
      status: "failed" as const,
      recordCount: records.length,
      error: "Presented TLS certificate did not match any TLSA record.",
    };

    throw discoveryError(
      "DANE_TLSA_MISMATCH",
      dane.error,
      { host, port, recordName, recordCount: records.length },
    );
  }

  return {
    dane: {
      ...base,
      status: "validated",
      recordCount: records.length,
      matchedRecord: {
        certUsage: matchedRecord.certUsage,
        selector: matchedRecord.selector,
        matchingType: matchedRecord.matchingType,
      },
    },
    warnings: [],
  };
}

function handleMissingTlsaRecords(
  url: URL,
  policy: ManifestFetchPolicy,
  dane: ManifestDaneMetadata,
): { dane: ManifestDaneMetadata; warnings: ParseWarning[] } {
  const message = `No TLSA records found for ${dane.recordName}; falling back to normal TLS validation.`;

  if (policy.requireTlsa) {
    throw discoveryError(
      "DANE_TLSA_REQUIRED",
      `TLSA records are required for ${normalizeHost(url.hostname)} but none were found.`,
      { host: normalizeHost(url.hostname), recordName: dane.recordName },
    );
  }

  return {
    dane,
    warnings: [createManifestWarning(url.toString(), message, "DANE_TLSA_LOOKUP_ERROR")],
  };
}

function createTlsaRecordName(hostname: string, port: number): string {
  return `_${port}._tcp.${normalizeHost(hostname)}`;
}

function normalizeTlsaRecord(record: ManifestTlsaRecord): NormalizedTlsaRecord {
  const matchingType = record.matchingType ?? record.match;
  const data = record.certificateAssociationData ?? record.data;

  if (!Number.isInteger(record.certUsage) || record.certUsage < 0 || record.certUsage > 3) {
    throw discoveryError("DANE_TLSA_LOOKUP_ERROR", "TLSA certUsage must be 0, 1, 2, or 3.");
  }

  if (record.selector !== 0 && record.selector !== 1) {
    throw discoveryError("DANE_TLSA_LOOKUP_ERROR", "TLSA selector must be 0 or 1.");
  }

  if (matchingType !== 0 && matchingType !== 1 && matchingType !== 2) {
    throw discoveryError("DANE_TLSA_LOOKUP_ERROR", "TLSA matching type must be 0, 1, or 2.");
  }

  if (data === undefined) {
    throw discoveryError(
      "DANE_TLSA_LOOKUP_ERROR",
      "TLSA record is missing certificate association data.",
    );
  }

  return {
    certUsage: record.certUsage,
    selector: record.selector,
    matchingType,
    certificateAssociationData: decodeTlsaAssociationData(data),
  };
}

function decodeTlsaAssociationData(value: string | ArrayBuffer | Uint8Array): Buffer {
  if (typeof value === "string") {
    const trimmed = value.trim();
    const hex = trimmed.replace(/^0x/i, "");

    if (/^[0-9a-f]+$/i.test(hex) && hex.length % 2 === 0) {
      return Buffer.from(hex, "hex");
    }

    if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
      throw discoveryError(
        "DANE_TLSA_LOOKUP_ERROR",
        "TLSA certificate association data must be hex, base64, or base64url.",
      );
    }

    const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
    return Buffer.from(padded, "base64");
  }

  if (value instanceof ArrayBuffer) {
    return Buffer.from(value);
  }

  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function readPeerCertificateChain(response: { socket?: unknown }): PeerCertificate[] {
  const socket = response.socket as
    | { getPeerCertificate?: (detailed?: boolean) => PeerCertificate | null }
    | undefined;
  const leaf = socket?.getPeerCertificate?.(true);

  if (!leaf) {
    throw discoveryError(
      "DANE_TLSA_MISMATCH",
      "TLSA validation is configured, but the peer certificate was unavailable.",
    );
  }

  const certificates: PeerCertificate[] = [];
  const seen = new Set<string>();
  let current: PeerCertificate | undefined = leaf;

  while (current?.raw) {
    const fingerprint = current.raw.toString("base64");

    if (seen.has(fingerprint)) {
      break;
    }

    certificates.push(current);
    seen.add(fingerprint);

    if (!current.issuerCertificate || current.issuerCertificate === current) {
      break;
    }

    current = current.issuerCertificate;
  }

  if (certificates.length === 0) {
    certificates.push(leaf);
  }

  return certificates;
}

function findMatchingTlsaRecord(
  records: NormalizedTlsaRecord[],
  certificates: PeerCertificate[],
): NormalizedTlsaRecord | undefined {
  return records.find((record) => {
    const candidateCertificates =
      record.certUsage === 0 || record.certUsage === 2 ? certificates : certificates.slice(0, 1);

    return candidateCertificates.some((certificate) => doesTlsaRecordMatchCertificate(record, certificate));
  });
}

function doesTlsaRecordMatchCertificate(
  record: NormalizedTlsaRecord,
  certificate: PeerCertificate,
): boolean {
  const selected = selectTlsaCertificateBytes(certificate, record.selector);
  const matched = applyTlsaMatchingType(selected, record.matchingType);

  return matched.equals(record.certificateAssociationData);
}

function selectTlsaCertificateBytes(certificate: PeerCertificate, selector: number): Buffer {
  if (selector === 0) {
    if (!Buffer.isBuffer(certificate.raw)) {
      throw discoveryError("DANE_TLSA_MISMATCH", "TLSA selector 0 requires raw certificate bytes.");
    }

    return certificate.raw;
  }

  if (Buffer.isBuffer(certificate.raw)) {
    const x509 = new X509Certificate(certificate.raw);
    return Buffer.from(x509.publicKey.export({ format: "der", type: "spki" }));
  }

  if (Buffer.isBuffer(certificate.pubkey)) {
    return certificate.pubkey;
  }

  throw discoveryError(
    "DANE_TLSA_MISMATCH",
    "TLSA selector 1 requires certificate public key bytes.",
  );
}

function applyTlsaMatchingType(value: Buffer, matchingType: number): Buffer {
  if (matchingType === 0) {
    return value;
  }

  if (matchingType === 1) {
    return createHash("sha256").update(value).digest();
  }

  return createHash("sha512").update(value).digest();
}

function isDnsNoRecordsError(error: unknown): boolean {
  if (!error || typeof error !== "object") {
    return false;
  }

  const code = "code" in error ? String(error.code) : "";
  return code === "ENODATA" || code === "ENOTFOUND" || code === "NOTFOUND";
}

function findTlsPinsForHostname(
  hostname: string,
  tlsPins: Record<string, string[]> | undefined,
): string[] {
  if (!tlsPins) {
    return [];
  }

  return tlsPins[normalizeHost(hostname)] ?? [];
}

function readResponseSpkiSha256(response: { socket?: unknown }): string {
  const socket = response.socket as
    | { getPeerCertificate?: (detailed?: boolean) => { raw?: Buffer; pubkey?: Buffer } | null }
    | undefined;
  const certificate = socket?.getPeerCertificate?.(true);

  if (!certificate) {
    throw discoveryError(
      "MANIFEST_TLS_PIN_MISMATCH",
      "TLS SPKI pinning is configured, but the peer certificate was unavailable.",
    );
  }

  if (Buffer.isBuffer(certificate.raw)) {
    const x509 = new X509Certificate(certificate.raw);
    const spki = x509.publicKey.export({ format: "der", type: "spki" });
    return createHash("sha256").update(spki).digest("base64");
  }

  if (Buffer.isBuffer(certificate.pubkey)) {
    return createHash("sha256").update(certificate.pubkey).digest("base64");
  }

  throw discoveryError(
    "MANIFEST_TLS_PIN_MISMATCH",
    "TLS SPKI pinning is configured, but no public key material was available.",
  );
}

function normalizeSpkiPin(pin: string): string {
  return pin.trim().replace(/^sha256\//i, "");
}

function isAllowedJsonContentType(
  contentType: string | undefined,
  allowMissingContentType: boolean,
): boolean {
  if (!contentType) {
    return allowMissingContentType;
  }

  const [mediaType] = contentType.split(";", 1);
  return mediaType?.trim().toLowerCase() === "application/json";
}
