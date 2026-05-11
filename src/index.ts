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
  ManifestFetcher,
  NormalizedDiscoveryResult,
  ParsedTxtRecords,
  ParseWarning,
  PosemeshDiscoveryRecord,
  PosemeshManifest,
  Relay,
  TxtResolver,
} from "./types.ts";
