export { discoverPosemesh } from "./discover.ts";
export { demoManifestFetcher, demoManifests, demoNames, demoTxtRecords } from "./demo.ts";
export { fetchPosemeshManifest, parsePosemeshManifest } from "./manifest.ts";
export { assertValidPosemeshName, normalizeName, validatePosemeshName } from "./name.ts";
export {
  parseAgentIdentityTxt,
  parsePosemeshTxt,
  parseTxtRecord,
  parseTxtRecords,
} from "./parser.ts";
export { DnsResolver, MockResolver } from "./resolvers.ts";
export type {
  BootstrapNode,
  DiscoverPosemeshOptions,
  DomainManager,
  FetchPosemeshManifestOptions,
  ManifestFetcher,
  ManifestHostResolver,
  ManifestHttpsRequest,
  ManifestResolvedAddress,
  NormalizedDiscoveryResult,
  PathfindingService,
  ParsedTxtRecords,
  ParseWarning,
  PosemeshDiscoveryRecord,
  PosemeshManifest,
  PosemeshServiceEndpoint,
  ReconstructionNode,
  Relay,
  SplatterNode,
  TxtResolver,
  VlmNode,
  WalletReference,
} from "./types.ts";
