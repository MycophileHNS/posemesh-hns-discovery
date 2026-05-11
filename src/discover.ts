import { fetchPosemeshManifest } from "./manifest.ts";
import { assertValidPosemeshName, normalizeName } from "./name.ts";
import { parseTxtRecords } from "./parser.ts";
import { DnsResolver } from "./resolvers.ts";
import type {
  DiscoverPosemeshOptions,
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
  const manifestUrl = selectManifestUrl(parsedTxt.records, warnings);
  let manifest: PosemeshManifest | undefined;

  if (manifestUrl && shouldFetchManifest) {
    try {
      manifest = await (options.manifestFetcher ?? fetchPosemeshManifest)(
        manifestUrl,
        options.manifestFetchOptions,
      );
      const identityWarning = validateManifestIdentity(normalizedName, manifest, manifestUrl);

      if (identityWarning) {
        warnings.push(identityWarning);
        manifest = undefined;
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
  });
}

interface NormalizeInput {
  name: string;
  records: ReturnType<typeof parseTxtRecords>["records"];
  warnings: ReturnType<typeof parseTxtRecords>["warnings"];
  manifest?: PosemeshManifest;
  manifestUrl?: string;
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
    agentEndpoints: uniqueStrings(agentEndpoints),
    resolvedAt: input.resolvedAt,
    warnings: input.warnings,
  };
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
    return undefined;
  }

  if (normalizeName(manifest.sourceName).toLowerCase() === normalizeName(name).toLowerCase()) {
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
