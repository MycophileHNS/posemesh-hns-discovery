import { fetchPosemeshManifestWithVerification } from "./manifest.ts";
import { assertValidPosemeshName, normalizeName } from "./name.ts";
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
import { parseTxtRecords } from "./parser.ts";
import { DnsResolver } from "./resolvers.ts";
import type {
  DiscoverPosemeshOptions,
  FetchPosemeshManifestOptions,
  ManifestCacheMetadata,
  ManifestDaneMetadata,
  ManifestVerificationKey,
  ManifestVerificationResult,
  NormalizedDiscoveryResult,
  PosemeshManifest,
  PosemeshServiceEndpoint,
  TlsaResolver,
} from "./types.ts";

export async function discoverPosemesh(
  name: string,
  options: DiscoverPosemeshOptions = {},
): Promise<NormalizedDiscoveryResult> {
  const normalizedName = assertValidPosemeshName(name);
  logDebug(options.logger, "Starting Posemesh discovery", { name: normalizedName }, options.redaction);
  const resolver =
    options.resolver ??
    new DnsResolver(options.dnsServer, options.dnsServer ? `dns:${options.dnsServer}` : "dns", {
      ...(options.logger ? { logger: options.logger } : {}),
      ...(options.redaction ? { redaction: options.redaction } : {}),
    });
  let txtRecords: string[];

  try {
    txtRecords = await resolver.resolveTxt(normalizedName);
  } catch (error) {
    logError(
      options.logger,
      "TXT lookup failed during Posemesh discovery",
      { name: normalizedName, ...errorLogFields(error, "TXT_LOOKUP_ERROR") },
      options.redaction,
    );
    throw discoveryError(
      getErrorCode(error, "TXT_LOOKUP_ERROR"),
      `TXT lookup failed for ${normalizedName}: ${getErrorMessage(error)}`,
      { name: normalizedName },
      error,
    );
  }

  const parsedTxt = parseTxtRecords(txtRecords, {
    ...(options.parserLimits ? { limits: options.parserLimits } : {}),
    ...(options.logger ? { logger: options.logger } : {}),
    ...(options.redaction ? { redaction: options.redaction } : {}),
  });
  const shouldFetchManifest = options.fetchManifest ?? true;
  const warnings = [...parsedTxt.warnings];
  appendDiscoveryRecordWarning(normalizedName, txtRecords, parsedTxt.records, warnings);
  const manifestUrl = selectManifestUrl(parsedTxt.records, warnings);
  const manifestFetchOptions = createManifestFetchOptions(
    normalizedName,
    manifestUrl,
    parsedTxt.records,
    options.manifestFetchOptions,
    options.tlsaResolver,
    options.logger,
    options.redaction,
  );
  let manifest: PosemeshManifest | undefined;
  let manifestVerification: ManifestVerificationResult | undefined;
  let manifestCache: ManifestCacheMetadata | undefined;
  let manifestDane: ManifestDaneMetadata | undefined;

  if (manifestUrl && shouldFetchManifest) {
    try {
      if (options.manifestFetcher) {
        manifest = await options.manifestFetcher(manifestUrl, manifestFetchOptions);
      } else {
        const fetched = await fetchPosemeshManifestWithVerification(
          manifestUrl,
          manifestFetchOptions,
        );
        manifest = fetched.manifest;
        manifestVerification = fetched.verification;
        manifestCache = fetched.cache;
        manifestDane = fetched.dane;
        warnings.push(...(fetched.warnings ?? []));
      }

      const identityWarning = validateManifestIdentity(normalizedName, manifest, manifestUrl);

      if (identityWarning) {
        warnings.push(identityWarning);
        manifest = undefined;
        manifestVerification = undefined;
        manifestCache = undefined;
        manifestDane = undefined;
      }
    } catch (error) {
      const warning = createWarning({
        source: "manifest",
        url: manifestUrl,
        code: getErrorCode(error, "MANIFEST_FETCH_ERROR"),
        message: getErrorMessage(error, "Unknown manifest fetch error."),
      });
      warnings.push(warning);
      logWarn(
        options.logger,
        "Manifest fetch warning during Posemesh discovery",
        { name: normalizedName, url: manifestUrl, code: warning.code ?? "MANIFEST_FETCH_ERROR" },
        options.redaction,
      );
    }
  }

  const result = normalizeDiscoveryResult({
    name: normalizedName,
    records: parsedTxt.records,
    warnings,
    resolvedAt: (options.now ?? (() => new Date()))().toISOString(),
    ...(manifest ? { manifest } : {}),
    ...(manifestUrl ? { manifestUrl } : {}),
    ...(manifestVerification ? { manifestVerification } : {}),
    ...(manifestCache ? { manifestCache } : {}),
    ...(manifestDane ? { manifestDane } : {}),
  });

  logInfo(
    options.logger,
    "Finished Posemesh discovery",
    {
      name: normalizedName,
      capabilityCount: result.capabilities.length,
      publicKeyCount: result.publicKeys.length,
      warningCount: result.warnings.length,
    },
    options.redaction,
  );

  return result;
}

interface NormalizeInput {
  name: string;
  records: ReturnType<typeof parseTxtRecords>["records"];
  warnings: ReturnType<typeof parseTxtRecords>["warnings"];
  manifest?: PosemeshManifest;
  manifestUrl?: string;
  manifestVerification?: ManifestVerificationResult;
  manifestCache?: ManifestCacheMetadata;
  manifestDane?: ManifestDaneMetadata;
  resolvedAt: string;
}

function normalizeDiscoveryResult(input: NormalizeInput): NormalizedDiscoveryResult {
  const txtCapabilities = input.records.flatMap((record) => record.capabilities);
  const txtPublicKeys = input.records.flatMap((record) => record.publicKeys);
  const agentEndpoints = input.records.flatMap((record) => record.agentEndpointUrl ?? []);
  const serviceEndpoints = collectServiceEndpoints(input.manifest);

  return {
    name: input.name,
    sourceName: input.manifest?.sourceName ?? input.name,
    regions: input.manifest?.regions ?? [],
    domainManagers: input.manifest?.domainManagers ?? [],
    relays: input.manifest?.relays ?? [],
    reconstructionNodes: input.manifest?.reconstructionNodes ?? [],
    splatterNodes: input.manifest?.splatterNodes ?? [],
    vlmNodes: input.manifest?.vlmNodes ?? [],
    pathfindingServices: input.manifest?.pathfindingServices ?? [],
    bootstrapNodes: input.manifest?.bootstrapNodes ?? [],
    wallets: input.manifest?.wallets ?? [],
    publicKeys: uniqueStrings([
      ...txtPublicKeys,
      ...(input.manifest?.publicKeys ?? []),
      ...(input.manifest?.wallets ?? []).flatMap((wallet) => wallet.publicKey ?? []),
      ...serviceEndpoints.flatMap((endpoint) => endpoint.publicKey ?? []),
    ]),
    capabilities: uniqueStrings([
      ...txtCapabilities,
      ...(input.manifest?.capabilities ?? []),
      ...serviceEndpoints.flatMap((endpoint) => endpoint.capabilities ?? []),
    ]),
    ...(input.manifest?.healthCheck ? { healthCheck: input.manifest.healthCheck } : {}),
    ...(input.manifestUrl ? { manifestUrl: input.manifestUrl } : {}),
    ...(input.manifestVerification ? { manifestVerification: input.manifestVerification } : {}),
    ...(input.manifestCache ? { manifestCache: input.manifestCache } : {}),
    ...(input.manifestDane ? { manifestDane: input.manifestDane } : {}),
    agentEndpoints: uniqueStrings(agentEndpoints),
    resolvedAt: input.resolvedAt,
    warnings: input.warnings,
  };
}

function createManifestFetchOptions(
  name: string,
  manifestUrl: string | undefined,
  records: ReturnType<typeof parseTxtRecords>["records"],
  options: FetchPosemeshManifestOptions | undefined,
  tlsaResolver: TlsaResolver | undefined,
  logger: DiscoverPosemeshOptions["logger"],
  redaction: DiscoverPosemeshOptions["redaction"],
): FetchPosemeshManifestOptions {
  const anchoredKeys = collectManifestVerificationKeys(records);
  const trustedKeys = uniqueVerificationKeys([...(options?.trustedKeys ?? []), ...anchoredKeys]);
  const resolvedLogger = options?.logger ?? logger;
  const resolvedRedaction = options?.redaction ?? redaction;
  const fetchOptions: FetchPosemeshManifestOptions = {
    ...(options ?? {}),
    trustedKeys,
    expectedName: options?.expectedName ?? name,
    ...(manifestUrl ? { expectedManifestUrl: options?.expectedManifestUrl ?? manifestUrl } : {}),
    ...(resolvedLogger ? { logger: resolvedLogger } : {}),
    ...(resolvedRedaction ? { redaction: resolvedRedaction } : {}),
  };

  if (!fetchOptions.resolveTlsa && tlsaResolver) {
    fetchOptions.resolveTlsa = tlsaResolver.resolveTlsa.bind(tlsaResolver);
  }

  return fetchOptions;
}

function collectManifestVerificationKeys(
  records: ReturnType<typeof parseTxtRecords>["records"],
): ManifestVerificationKey[] {
  return records.flatMap((record) => record.verificationKeys);
}

function uniqueVerificationKeys(keys: ManifestVerificationKey[]): ManifestVerificationKey[] {
  const seen = new Set<string>();

  return keys.filter((key) => {
    const id = key.id ?? "";
    const cacheKey = [
      key.source,
      key.algorithm,
      id,
      key.publicKey,
      key.notBefore ?? "",
      key.notAfter ?? "",
    ].join(":");

    if (seen.has(cacheKey)) {
      return false;
    }

    seen.add(cacheKey);
    return true;
  });
}

function appendDiscoveryRecordWarning(
  name: string,
  txtRecords: string[],
  records: ReturnType<typeof parseTxtRecords>["records"],
  warnings: ReturnType<typeof parseTxtRecords>["warnings"],
): void {
  if (txtRecords.length === 0) {
    warnings.push(createWarning({
      source: "txt",
      code: "TXT_NO_RECORDS",
      message: `No TXT records found for ${name}. Live lookups require a Handshake-aware resolver.`,
    }));
    return;
  }

  if (records.length === 0 && warnings.length === 0) {
    warnings.push(createWarning({
      source: "txt",
      code: "TXT_NO_COMPATIBLE_RECORDS",
      message: `No compatible posemesh:v1 or agent-identity:v1 TXT records found for ${name}.`,
    }));
  }
}

function selectManifestUrl(
  records: ReturnType<typeof parseTxtRecords>["records"],
  warnings: ReturnType<typeof parseTxtRecords>["warnings"],
): string | undefined {
  const manifestUrls = uniqueStrings(records.flatMap((record) => record.manifestUrl ?? []));

  if (manifestUrls.length > 1) {
    warnings.push(createWarning({
      source: "txt",
      code: "TXT_AMBIGUOUS_MANIFEST",
      message:
        "Multiple distinct manifest URLs were found; skipping manifest fetch to avoid DNS TXT record ordering ambiguity.",
    }));
    return undefined;
  }

  return manifestUrls[0];
}

function validateManifestIdentity(
  name: string,
  manifest: PosemeshManifest,
  manifestUrl: string,
): ReturnType<typeof parseTxtRecords>["warnings"][number] | undefined {
  if (!manifest.sourceName) {
    return {
      source: "manifest",
      url: manifestUrl,
      code: "MANIFEST_BINDING_MISMATCH",
      message: `Manifest sourceName is required and must match requested name ${name}.`,
    };
  }

  if (normalizeName(manifest.sourceName).toLowerCase() === normalizeName(name).toLowerCase()) {
    if (
      manifest.name &&
      normalizeName(manifest.name).toLowerCase() !== normalizeName(name).toLowerCase()
    ) {
      return {
        source: "manifest",
        url: manifestUrl,
        code: "MANIFEST_BINDING_MISMATCH",
        message: `Manifest name ${manifest.name} does not match requested name ${name}.`,
      };
    }

    return undefined;
  }

  return {
    source: "manifest",
    url: manifestUrl,
    code: "MANIFEST_BINDING_MISMATCH",
    message: `Manifest sourceName ${manifest.sourceName} does not match requested name ${name}.`,
  };
}

function collectServiceEndpoints(manifest: PosemeshManifest | undefined): PosemeshServiceEndpoint[] {
  if (!manifest) {
    return [];
  }

  return [
    ...(manifest.domainManagers ?? []),
    ...(manifest.relays ?? []),
    ...(manifest.reconstructionNodes ?? []),
    ...(manifest.splatterNodes ?? []),
    ...(manifest.vlmNodes ?? []),
    ...(manifest.pathfindingServices ?? []),
    ...(manifest.bootstrapNodes ?? []),
  ];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))];
}
