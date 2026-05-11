export type DiscoveryRecordKind = "posemesh" | "agent-identity";

export interface DomainManager {
  id?: string;
  name?: string;
  endpoint: string;
  region?: string;
  publicKey?: string;
  capabilities?: string[];
}

export interface Relay {
  id?: string;
  endpoint: string;
  region?: string;
  transport?: string;
  publicKey?: string;
}

export interface BootstrapNode {
  id?: string;
  endpoint: string;
  transport?: string;
  publicKey?: string;
}

export interface PosemeshManifest {
  version: 1;
  name?: string;
  sourceName?: string;
  domainManagers?: DomainManager[];
  relays?: Relay[];
  bootstrapNodes?: BootstrapNode[];
  publicKeys?: string[];
  capabilities?: string[];
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
  domainManagers: DomainManager[];
  relays: Relay[];
  bootstrapNodes: BootstrapNode[];
  publicKeys: string[];
  capabilities: string[];
  manifestUrl?: string;
  resolvedAt: string;
}

export interface TxtResolver {
  resolveTxt(name: string): Promise<string[]>;
}

export interface ParseWarning {
  record: string;
  message: string;
}

export interface ParsedTxtRecords {
  records: PosemeshDiscoveryRecord[];
  warnings: ParseWarning[];
}

export type ManifestFetcher = (url: string) => Promise<PosemeshManifest>;

export interface DiscoverPosemeshOptions {
  allowAnyHandshakeName?: boolean;
  resolver?: TxtResolver;
  dnsServer?: string;
  fetchManifest?: boolean;
  manifestFetcher?: ManifestFetcher;
  now?: () => Date;
}
