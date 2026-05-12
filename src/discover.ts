import { fetchPosemeshManifestWithVerification } from "./manifest.ts";
import { assertValidPosemeshName, normalizeName } from "./name.ts";
import { parseTxtRecords } from "./parser.ts";
import { DnsResolver } from "./resolvers.ts";
import type {
  DiscoverPosemeshOptions,
  FetchPosemeshManifestOptions,
  ManifestVerificationKey,
  ManifestVerificationResult,
  NormalizedDiscoveryResult,
  PosemeshManifest,
  PosemeshServiceEndpoint,
} from "./types.ts";

export async function discoverPosemesh(
  name: string,
  options: DiscoverPosemeshOptions = {},
): Promise<NormalizedDiscoveryResult> {
  const normalizedName = assertValidPosemeshName(name);
  const resolver = options.resolver ?? new DnsResolver(options.dnsServer);
  const txtRecords = await resolver.resolveTxt(normalizedName);
  const parsedTxt = parseTxtRecords(txtRecords);
  const shouldFetchManifest = options.fetchManifest ?? true;
  const warnings = [...parsedTxt.warnings];
  appendDiscoveryRecordWarning(normalizedName, txtRecords, parsedTxt.records, warnings);
  const manifestUrl = selectManifestUrl(parsedTxt.records, warnings);
  const manifestFetchOptions = createManifestFetchOptions(
    normalizedName,
    manifestUrl,
    parsedTxt.records,
    options.manifestFetchOptions,
  );
  let manifest: PosemeshManifest | undefined;
  let manifestVerification: ManifestVerificationResult | undefined;

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
        warnings.push(...(fetched.warnings ?? []));
      }

      const identityWarning = validateManifestIdentity(normalizedName, manifest, manifestUrl);

      if (identityWarning) {
        warnings.push(identityWarning);
        manifest = undefined;
        manifestVerification = undefined;
      }
    } catch (error) {
      warnings.push({
        source: "manifest",
        url: manifestUrl,
        message: error instanceof Error ? error.message : "Unknown manifest fetch error.",
      });
    }
  }

  return normalizeDiscoveryResult({
    name: normalizedName,
    records: parsedTxt.records,
    warnings,
    resolvedAt: (options.now ?? (() => new Date()))().toISOString(),
    ...(manifest ? { manifest } : {}),
    ...(manifestUrl ? { manifestUrl } : {}),
    ...(manifestVerification ? { manifestVerification } : {}),
  });
}

interface NormalizeInput {
  name: string;
  records: ReturnType<typeof parseTxtRecords>["records"];
  warnings: ReturnType<typeof parseTxtRecords>["warnings"];
  manifest?: PosemeshManifest;
  manifestUrl?: string;
  manifestVerification?: ManifestVerificationResult;
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
): FetchPosemeshManifestOptions {
  const anchoredKeys = collectManifestVerificationKeys(records);
  const trustedKeys = uniqueVerificationKeys([...(options?.trustedKeys ?? []), ...anchoredKeys]);

  return {
    ...(options ?? {}),
    trustedKeys,
    expectedName: options?.expectedName ?? name,
    ...(manifestUrl ? { expectedManifestUrl: options?.expectedManifestUrl ?? manifestUrl } : {}),
  };
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
    const cacheKey = `${key.source}:${key.algorithm}:${id}:${key.publicKey}`;

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
    warnings.push({
      source: "txt",
      message: `No TXT records found for ${name}. Live lookups require a Handshake-aware resolver.`,
    });
    return;
  }

  if (records.length === 0 && warnings.length === 0) {
    warnings.push({
      source: "txt",
      message: `No compatible posemesh:v1 or agent-identity:v1 TXT records found for ${name}.`,
    });
  }
}

function selectManifestUrl(
  records: ReturnType<typeof parseTxtRecords>["records"],
  warnings: ReturnType<typeof parseTxtRecords>["warnings"],
): string | undefined {
  const manifestUrls = uniqueStrings(records.flatMap((record) => record.manifestUrl ?? []));

  if (manifestUrls.length > 1) {
    warnings.push({
      source: "txt",
      message:
        "Multiple distinct manifest URLs were found; skipping manifest fetch to avoid DNS TXT record ordering ambiguity.",
    });
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
        message: `Manifest name ${manifest.name} does not match requested name ${name}.`,
      };
    }

    return undefined;
  }

  return {
    source: "manifest",
    url: manifestUrl,
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
