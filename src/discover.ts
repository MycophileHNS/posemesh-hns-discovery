import { fetchPosemeshManifest } from "./manifest.ts";
import { assertValidPosemeshName } from "./name.ts";
import { parseTxtRecords } from "./parser.ts";
import { DnsResolver } from "./resolvers.ts";
import type {
  DiscoverPosemeshOptions,
  NormalizedDiscoveryResult,
  PosemeshManifest,
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
    resolvedAt: (options.now ?? (() => new Date()))().toISOString(),
    ...(manifest ? { manifest } : {}),
    ...(firstManifestUrl ? { manifestUrl: firstManifestUrl } : {}),
  });
}

interface NormalizeInput {
  name: string;
  records: ReturnType<typeof parseTxtRecords>["records"];
  manifest?: PosemeshManifest;
  manifestUrl?: string;
  resolvedAt: string;
}

function normalizeDiscoveryResult(input: NormalizeInput): NormalizedDiscoveryResult {
  const txtCapabilities = input.records.flatMap((record) => record.capabilities);
  const txtPublicKeys = input.records.flatMap((record) => record.publicKeys);

  return {
    name: input.name,
    sourceName: input.manifest?.sourceName ?? input.manifest?.name ?? input.name,
    domainManagers: input.manifest?.domainManagers ?? [],
    relays: input.manifest?.relays ?? [],
    bootstrapNodes: input.manifest?.bootstrapNodes ?? [],
    publicKeys: uniqueStrings([
      ...txtPublicKeys,
      ...(input.manifest?.publicKeys ?? []),
      ...(input.manifest?.domainManagers ?? []).flatMap((manager) => manager.publicKey ?? []),
      ...(input.manifest?.relays ?? []).flatMap((relay) => relay.publicKey ?? []),
      ...(input.manifest?.bootstrapNodes ?? []).flatMap((node) => node.publicKey ?? []),
    ]),
    capabilities: uniqueStrings([
      ...txtCapabilities,
      ...(input.manifest?.capabilities ?? []),
      ...(input.manifest?.domainManagers ?? []).flatMap((manager) => manager.capabilities ?? []),
    ]),
    ...(input.manifestUrl ? { manifestUrl: input.manifestUrl } : {}),
    resolvedAt: input.resolvedAt,
  };
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))];
}
