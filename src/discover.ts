import { fetchPosemeshManifest } from "./manifest.ts";
import { assertValidPosemeshName } from "./name.ts";
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
  const normalizedName = assertValidPosemeshName(
    name,
    options.allowAnyHandshakeName === undefined
      ? {}
      : { allowAnyHandshakeName: options.allowAnyHandshakeName },
  );
  const resolver = options.resolver ?? new DnsResolver(options.dnsServer);
  const txtRecords = await resolver.resolveTxt(normalizedName);
  const parsedTxt = parseTxtRecords(txtRecords);
  const firstManifestUrl = parsedTxt.records.find((record) => record.manifestUrl)?.manifestUrl;
  const shouldFetchManifest = options.fetchManifest ?? true;
  const manifest = firstManifestUrl && shouldFetchManifest
    ? await (options.manifestFetcher ?? fetchPosemeshManifest)(firstManifestUrl)
    : undefined;

  return normalizeDiscoveryResult({
    name: normalizedName,
    records: parsedTxt.records,
    warnings: parsedTxt.warnings,
    resolvedAt: (options.now ?? (() => new Date()))().toISOString(),
    ...(manifest ? { manifest } : {}),
    ...(firstManifestUrl ? { manifestUrl: firstManifestUrl } : {}),
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
  const serviceEndpoints = collectServiceEndpoints(input.manifest);

  return {
    name: input.name,
    sourceName: input.manifest?.sourceName ?? input.manifest?.name ?? input.name,
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
    resolvedAt: input.resolvedAt,
    warnings: input.warnings,
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
