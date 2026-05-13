import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";

export type DiscoveryRecordKind = "posemesh" | "agent-identity";
export type ManifestSecurityMode = "strict" | "permissive" | "demo";
export type ManifestSignatureAlgorithm = "ed25519" | "ecdsa-p256-sha256";
export type ManifestCacheStatus = "fresh" | "stale" | "uncacheable";
export type ManifestDaneStatus = "not-requested" | "validated" | "no-records" | "failed";

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
  audience?: string[];
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
  /**
   * Optional ISO-8601 UTC activation time for key rotation.
   * Before this instant the key is ignored for manifest verification.
   */
  notBefore?: string;
  /**
   * Optional ISO-8601 UTC expiration time for key rotation.
   * After this instant the key is ignored for manifest verification.
   */
  notAfter?: string;
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
  keyNotBefore?: string;
  keyNotAfter?: string;
  verifiedAt: string;
  issuedAt?: string;
  expiresAt?: string;
}

export interface ManifestCacheMetadata {
  cacheStatus: ManifestCacheStatus;
  checkedAt: string;
  issuedAt?: string;
  expiresAt?: string;
  ageMs?: number;
  maxManifestAgeMs?: number;
  reason?: string;
}

export interface ManifestTlsaRecord {
  certUsage: number;
  selector: number;
  matchingType?: number;
  match?: number;
  certificateAssociationData?: string | ArrayBuffer | Uint8Array;
  data?: string | ArrayBuffer | Uint8Array;
}

export interface ManifestDaneMetadata {
  status: ManifestDaneStatus;
  checkedAt: string;
  host: string;
  port: number;
  recordName: string;
  recordCount: number;
  matchedRecord?: {
    certUsage: number;
    selector: number;
    matchingType: number;
  };
  error?: string;
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
  manifestCache?: ManifestCacheMetadata;
  manifestDane?: ManifestDaneMetadata;
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

/**
 * Resolves TLSA records for a manifest hostname. Production Handshake clients
 * should provide a Handshake-aware resolver here; the default implementation
 * uses Node's configured DNS resolver for compatibility with tests and demos.
 */
export type ManifestTlsaResolver = (
  hostname: string,
  port: number,
) => Promise<ManifestTlsaRecord[]>;

export interface FetchPosemeshManifestOptions {
  timeoutMs?: number;
  maxBytes?: number;
  resolveHostname?: ManifestHostResolver;
  httpsRequest?: ManifestHttpsRequest;
  securityMode?: ManifestSecurityMode;
  trustedKeys?: ManifestVerificationKey[];
  tlsPins?: Record<string, string[]>;
  /**
   * Opt in to DANE TLSA validation for the manifest host. When enabled and no
   * TLSA records exist, the fetch falls back to normal TLS and returns a warning.
   */
  enableDane?: boolean;
  /**
   * Require a matching TLSA record. This fails closed when records are missing,
   * lookup fails, or the presented certificate does not match.
   */
  requireTlsa?: boolean;
  /**
   * Optional TLSA resolver. Use this to plug in a Handshake-aware resolver for
   * `_443._tcp.<manifest-host>` records.
   */
  resolveTlsa?: ManifestTlsaResolver;
  allowMissingContentType?: boolean;
  expectedName?: string;
  expectedManifestUrl?: string;
  /**
   * Optional audience binding for signed manifest payloads. When set, signed
   * manifests must include at least one matching audience value outside demo mode.
   */
  expectedAudience?: string | string[];
  now?: () => Date;
  maxClockSkewMs?: number;
  maxManifestTtlMs?: number;
  maxManifestAgeMs?: number;
}

export interface FetchedPosemeshManifest {
  manifest: PosemeshManifest;
  verification: ManifestVerificationResult;
  cache: ManifestCacheMetadata;
  dane?: ManifestDaneMetadata;
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
