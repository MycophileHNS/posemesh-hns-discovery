export type DiscoveryRecordKind = "posemesh" | "agent-identity";

export interface PosemeshServiceEndpoint {
  id?: string;
  name?: string;
  endpoint: string;
  region?: string;
  transport?: string;
  publicKey?: string;
  capabilities?: string[];
  healthCheck?: string;
}

export interface DomainManager extends PosemeshServiceEndpoint {
  wallet?: string;
}

export interface Relay extends PosemeshServiceEndpoint {
  sessionPolicy?: string;
}

export interface BootstrapNode extends PosemeshServiceEndpoint {}

export interface ReconstructionNode extends PosemeshServiceEndpoint {}

export interface SplatterNode extends PosemeshServiceEndpoint {}

export interface VlmNode extends PosemeshServiceEndpoint {
  models?: string[];
}

export interface PathfindingService extends PosemeshServiceEndpoint {}

export interface WalletReference {
  address: string;
  chain?: string;
  role?: string;
  publicKey?: string;
}

export interface PosemeshManifest {
  version: 1;
  name?: string;
  sourceName?: string;
  regions?: string[];
  domainManagers?: DomainManager[];
  relays?: Relay[];
  reconstructionNodes?: ReconstructionNode[];
  splatterNodes?: SplatterNode[];
  vlmNodes?: VlmNode[];
  pathfindingServices?: PathfindingService[];
  bootstrapNodes?: BootstrapNode[];
  wallets?: WalletReference[];
  publicKeys?: string[];
  capabilities?: string[];
  healthCheck?: string;
  signature?: string;
}

export interface PosemeshDiscoveryRecord {
  kind: DiscoveryRecordKind;
  version: 1;
  raw: string;
  manifestUrl?: string;
  publicKeys: string[];
  capabilities: string[];
}

export interface NormalizedDiscoveryResult {
  name: string;
  sourceName: string;
  regions: string[];
  domainManagers: DomainManager[];
  relays: Relay[];
  reconstructionNodes: ReconstructionNode[];
  splatterNodes: SplatterNode[];
  vlmNodes: VlmNode[];
  pathfindingServices: PathfindingService[];
  bootstrapNodes: BootstrapNode[];
  wallets: WalletReference[];
  publicKeys: string[];
  capabilities: string[];
  healthCheck?: string;
  manifestUrl?: string;
  resolvedAt: string;
  warnings: ParseWarning[];
}

export interface TxtResolver {
  resolveTxt(name: string): Promise<string[]>;
}

export interface ParseWarning {
  source: "txt" | "manifest";
  record?: string;
  url?: string;
  message: string;
}

export interface ParsedTxtRecords {
  records: PosemeshDiscoveryRecord[];
  warnings: ParseWarning[];
}

export interface ManifestResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type ManifestHostResolver = (hostname: string) => Promise<ManifestResolvedAddress[]>;

export interface FetchPosemeshManifestOptions {
  timeoutMs?: number;
  maxBytes?: number;
  resolveHostname?: ManifestHostResolver;
}

export type ManifestFetcher = (
  url: string,
  options?: FetchPosemeshManifestOptions,
) => Promise<PosemeshManifest>;

export interface DiscoverPosemeshOptions {
  resolver?: TxtResolver;
  dnsServer?: string;
  fetchManifest?: boolean;
  manifestFetchOptions?: FetchPosemeshManifestOptions;
  manifestFetcher?: ManifestFetcher;
  now?: () => Date;
}
