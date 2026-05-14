import type { ClientRequest, IncomingMessage } from "node:http";
import type { RequestOptions } from "node:https";

export type DiscoveryRecordKind = "posemesh" | "agent-identity";
export type ManifestSecurityMode = "strict" | "permissive" | "demo";
export type ManifestSignatureAlgorithm = "ed25519" | "ecdsa-p256-sha256";
export type ManifestCacheStatus = "fresh" | "stale" | "uncacheable";
export type ManifestDaneStatus = "not-requested" | "validated" | "no-records" | "failed";
export type DiscoveryErrorCode =
  | "UNKNOWN_ERROR"
  | "INVALID_POSEMESH_NAME"
  | "TXT_LOOKUP_ERROR"
  | "TXT_NO_RECORDS"
  | "TXT_NO_COMPATIBLE_RECORDS"
  | "TXT_PARSE_ERROR"
  | "TXT_LIMIT_EXCEEDED"
  | "TXT_AMBIGUOUS_MANIFEST"
  | "RESOLVER_LOOKUP_ERROR"
  | "RESOLVER_CONSENSUS_FAILED"
  | "RESOLVER_UNSUPPORTED"
  | "MANIFEST_FETCH_ERROR"
  | "MANIFEST_URL_INVALID"
  | "MANIFEST_URL_UNSAFE"
  | "MANIFEST_HTTP_ERROR"
  | "MANIFEST_REDIRECT_REJECTED"
  | "MANIFEST_CONTENT_TYPE_INVALID"
  | "MANIFEST_TOO_LARGE"
  | "MANIFEST_TIMEOUT"
  | "MANIFEST_TLS_PIN_MISMATCH"
  | "MANIFEST_PARSE_ERROR"
  | "MANIFEST_SCHEMA_INVALID"
  | "MANIFEST_SIGNATURE_REQUIRED"
  | "MANIFEST_SIGNATURE_INVALID"
  | "MANIFEST_KEY_REQUIRED"
  | "MANIFEST_KEY_INACTIVE"
  | "MANIFEST_REPLAY_INVALID"
  | "MANIFEST_BINDING_MISMATCH"
  | "MANIFEST_PUBLIC_KEY_INVALID"
  | "DANE_TLSA_LOOKUP_ERROR"
  | "DANE_TLSA_REQUIRED"
  | "DANE_TLSA_MISMATCH";

export type DiscoveryLogValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | DiscoveryLogValue[]
  | { [key: string]: DiscoveryLogValue };

export interface DiscoveryLogFields {
  [key: string]: DiscoveryLogValue;
}

export interface DiscoveryLogger {
  debug(message: string, fields?: DiscoveryLogFields): void;
  info(message: string, fields?: DiscoveryLogFields): void;
  warn(message: string, fields?: DiscoveryLogFields): void;
  error(message: string, fields?: DiscoveryLogFields): void;
}

export interface LoggerRedactionOptions {
  /**
   * Case-insensitive field names that should be replaced before data is sent
   * to the caller-provided logger.
   */
  redactKeys?: string[];
  replacement?: string;
}

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
  verified?: boolean;
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
  resolveTxtDetailed?(name: string): Promise<DetailedResolverResult<string>>;
}

export type CompositeResolverStrategy = "first-success" | "quorum" | "strict-consensus";
export type ResolverRecordType = "TXT" | "TLSA";
export type ResolverStatus = "ok" | "no-records" | "lookup-error" | "consensus-failed";

export interface DetailedResolverAttempt<TRecord> {
  resolver: string;
  status: Exclude<ResolverStatus, "consensus-failed">;
  records: TRecord[];
  code?: DiscoveryErrorCode;
  error?: string;
}

export interface DetailedResolverResult<TRecord> {
  name: string;
  type: ResolverRecordType;
  status: ResolverStatus;
  records: TRecord[];
  resolver?: string;
  code?: DiscoveryErrorCode;
  error?: string;
  attempts?: DetailedResolverAttempt<TRecord>[];
}

export interface ParseWarning {
  source: "txt" | "manifest";
  record?: string;
  url?: string;
  code?: DiscoveryErrorCode;
  message: string;
}

export interface ParsedTxtRecords {
  records: PosemeshDiscoveryRecord[];
  warnings: ParseWarning[];
}

export interface ParserLimits {
  maxTxtRecords?: number;
  maxTxtRecordBytes?: number;
  maxTotalTxtBytes?: number;
  maxFieldsPerRecord?: number;
  maxFieldNameBytes?: number;
  maxFieldValueBytes?: number;
  maxCapabilities?: number;
  maxPublicKeys?: number;
  maxAgentIdentityBytes?: number;
}

export interface ParserOptions {
  limits?: ParserLimits;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

export interface ManifestLimits {
  maxStringBytes?: number;
  maxUrlBytes?: number;
  maxArrayItems?: number;
  maxCapabilities?: number;
  maxPublicKeys?: number;
  maxServicesPerCategory?: number;
  maxTotalServices?: number;
  maxWallets?: number;
  maxRegions?: number;
  maxAudience?: number;
  maxModels?: number;
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
 * Resolves TLSA records for a manifest hostname and port.
 *
 * Production Handshake clients should provide a trusted Handshake-aware resolver
 * path here. The built-in fallback uses Node's configured DNS resolver only for
 * compatibility with tests, demos, and conventional DNS hosts; it does not make
 * the process Handshake-aware by itself.
 */
export type ManifestTlsaResolver = (
  hostname: string,
  port: number,
) => Promise<ManifestTlsaRecord[]>;

export interface TlsaResolver {
  resolveTlsa(hostname: string, port: number): Promise<ManifestTlsaRecord[]>;
  resolveTlsaDetailed?(
    hostname: string,
    port: number,
  ): Promise<DetailedResolverResult<ManifestTlsaRecord>>;
}

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
  manifestLimits?: ManifestLimits;
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
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

export interface FetchedPosemeshManifest {
  manifest: PosemeshManifest;
  verification: ManifestVerificationResult;
  cache: ManifestCacheMetadata;
  dane?: ManifestDaneMetadata;
  warnings?: ParseWarning[];
}

/**
 * Optional manifest fetching override.
 *
 * This is a trust boundary: a custom fetcher bypasses the built-in HTTPS safety
 * checks, strict Content-Type enforcement, DANE/TLS pin checks, and signature
 * parsing unless it returns a verified FetchedPosemeshManifest. In the default
 * strict mode, plain PosemeshManifest results are treated as unverified and are
 * rejected or downgraded to warnings. Use `securityMode: "demo"` or
 * `"permissive"` only for prototype-only custom fetching.
 */
export type ManifestFetcher = (
  url: string,
  options?: FetchPosemeshManifestOptions,
) => Promise<PosemeshManifest | FetchedPosemeshManifest>;

export interface DiscoverPosemeshOptions {
  resolver?: TxtResolver;
  tlsaResolver?: TlsaResolver;
  dnsServer?: string;
  parserLimits?: ParserLimits;
  fetchManifest?: boolean;
  /**
   * Fail closed unless an unambiguous manifest is fetched and accepted.
   * Keep this false for demos; set true for production-style callers that do
   * not want silent TXT-only downgrade when manifest discovery fails.
   */
  requireManifest?: boolean;
  manifestFetchOptions?: FetchPosemeshManifestOptions;
  manifestFetcher?: ManifestFetcher;
  now?: () => Date;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}
