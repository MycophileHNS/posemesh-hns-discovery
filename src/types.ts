import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";

export type DiscoveryRecordKind = "posemesh" | "agent-identity";
export type ManifestSecurityMode = "strict" | "permissive" | "demo";
export type ManifestSignatureAlgorithm = "ed25519" | "ecdsa-p256-sha256";

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
  manifestUrl?: string;
  issuedAt?: string;
  expiresAt?: string;
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
  agentEndpointUrl?: string;
  publicKeys: string[];
  verificationKeys: ManifestVerificationKey[];
  capabilities: string[];
}

export interface ManifestVerificationKey {
  id?: string;
  algorithm: ManifestSignatureAlgorithm;
  publicKey: string;
  source: "txt" | "trusted";
}

export interface SignedPosemeshManifestEnvelope {
  version: 1;
  payload: string;
  signature: string;
  algorithm: ManifestSignatureAlgorithm;
  keyId?: string;
}

export interface ManifestVerificationResult {
  status: "verified" | "unsigned-allowed" | "invalid-allowed";
  algorithm?: ManifestSignatureAlgorithm;
  keyId?: string;
  keySource?: ManifestVerificationKey["source"];
  verifiedAt: string;
  issuedAt?: string;
  expiresAt?: string;
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
  manifestVerification?: ManifestVerificationResult;
  agentEndpoints: string[];
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
export type ManifestHttpsRequest = (
  options: RequestOptions,
  callback?: (response: IncomingMessage) => void,
) => ClientRequest;

export interface FetchPosemeshManifestOptions {
  timeoutMs?: number;
  maxBytes?: number;
  resolveHostname?: ManifestHostResolver;
  httpsRequest?: ManifestHttpsRequest;
  securityMode?: ManifestSecurityMode;
  trustedKeys?: ManifestVerificationKey[];
  expectedName?: string;
  expectedManifestUrl?: string;
  now?: () => Date;
  maxClockSkewMs?: number;
  maxManifestTtlMs?: number;
}

export interface FetchedPosemeshManifest {
  manifest: PosemeshManifest;
  verification: ManifestVerificationResult;
  warnings?: ParseWarning[];
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
