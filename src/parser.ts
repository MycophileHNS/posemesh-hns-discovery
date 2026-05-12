import { parsePublicKey } from "./public-keys.ts";
import { parseManifestSignatureAlgorithm } from "./security.ts";
import type {
  ManifestSignatureAlgorithm,
  ManifestVerificationKey,
  ParsedTxtRecords,
  PosemeshDiscoveryRecord,
} from "./types.ts";

const POSEMESH_PREFIX = "posemesh:v1";
const AGENT_IDENTITY_PREFIX = "agent-identity:v1=";

export function parseTxtRecords(txtRecords: string[]): ParsedTxtRecords {
  const parsed: PosemeshDiscoveryRecord[] = [];
  const warnings: ParsedTxtRecords["warnings"] = [];

  for (const record of txtRecords) {
    try {
      const discoveryRecord = parseTxtRecord(record);

      if (discoveryRecord) {
        parsed.push(discoveryRecord);
      }
    } catch (error) {
      warnings.push({
        source: "txt",
        record,
        message: error instanceof Error ? error.message : "Unknown TXT parsing error.",
      });
    }
  }

  return { records: parsed, warnings };
}

export function parseTxtRecord(record: string): PosemeshDiscoveryRecord | undefined {
  const trimmed = record.trim();

  if (trimmed.startsWith(POSEMESH_PREFIX)) {
    return parsePosemeshTxt(trimmed);
  }

  if (trimmed.startsWith(AGENT_IDENTITY_PREFIX)) {
    return parseAgentIdentityTxt(trimmed);
  }

  return undefined;
}

export function parsePosemeshTxt(record: string): PosemeshDiscoveryRecord {
  const [prefix, ...parts] = record.split(";").map((part) => part.trim());

  if (prefix !== POSEMESH_PREFIX) {
    throw new Error("Unsupported posemesh TXT version.");
  }

  const values = new Map<string, string>();

  for (const part of parts) {
    if (!part) {
      continue;
    }

    const separator = part.indexOf("=");

    if (separator === -1) {
      throw new Error(`Invalid posemesh TXT field: ${part}`);
    }

    const key = part.slice(0, separator).trim();
    const value = part.slice(separator + 1).trim();

    if (!key || !value) {
      throw new Error(`Invalid posemesh TXT field: ${part}`);
    }

    values.set(key, value);
  }

  const manifestUrl = values.get("manifest");
  const publicKey = values.get("publicKey");
  const keyId = values.get("keyId");
  const algorithm = parseOptionalAlgorithm(values.get("alg"));
  const capabilities = splitCsv(values.get("capabilities"));
  const publicKeys = publicKey ? [parsePublicKey(publicKey, "TXT field publicKey")] : [];

  const result: PosemeshDiscoveryRecord = {
    kind: "posemesh",
    version: 1,
    raw: record,
    publicKeys,
    verificationKeys: createVerificationKeys(publicKeys, algorithm, keyId),
    capabilities,
  };

  if (manifestUrl) {
    result.manifestUrl = parseHttpsUrl(manifestUrl, "manifest");
  }

  return result;
}

export function parseAgentIdentityTxt(record: string): PosemeshDiscoveryRecord {
  const jsonText = record.slice(AGENT_IDENTITY_PREFIX.length).trim();
  const parsed = JSON.parse(jsonText) as unknown;

  if (!isRecord(parsed)) {
    throw new Error("agent-identity payload must be a JSON object.");
  }

  if (parsed.version !== 1) {
    throw new Error("Unsupported agent-identity version.");
  }

  const endpoint = requiredString(parsed.endpoint, "endpoint");
  const capabilities = optionalStringArray(parsed.capabilities, "capabilities");
  const publicKeys = extractPublicKeys(parsed);

  const result: PosemeshDiscoveryRecord = {
    kind: "agent-identity",
    version: 1,
    raw: record,
    publicKeys,
    verificationKeys: [],
    capabilities,
  };

  result.agentEndpointUrl = parseHttpsUrl(endpoint, "endpoint");

  return result;
}

function createVerificationKeys(
  publicKeys: string[],
  algorithm: ManifestSignatureAlgorithm,
  keyId: string | undefined,
): ManifestVerificationKey[] {
  return publicKeys.map((publicKey) => ({
    ...(keyId ? { id: keyId } : {}),
    algorithm,
    publicKey,
    source: "txt",
  }));
}

function parseOptionalAlgorithm(value: string | undefined): ManifestSignatureAlgorithm {
  if (!value) {
    return "ed25519";
  }

  return parseManifestSignatureAlgorithm(value, "TXT field alg");
}

function splitCsv(value: string | undefined): string[] {
  if (!value) {
    return [];
  }

  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function extractPublicKeys(value: Record<string, unknown>): string[] {
  const publicKeys = optionalStringArray(value.publicKeys, "publicKeys");
  const publicKey = optionalString(value.publicKey, "publicKey");
  const parsedPublicKeys = publicKeys.map((key, index) =>
    parsePublicKey(key, `agent-identity field publicKeys[${index}]`),
  );

  if (publicKey) {
    return [...parsedPublicKeys, parsePublicKey(publicKey, "agent-identity field publicKey")];
  }

  return parsedPublicKeys;
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`agent-identity field ${field} must be a non-empty string.`);
  }

  return value.trim();
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`agent-identity field ${field} must be a non-empty string.`);
  }

  return value.trim();
}

function optionalStringArray(value: unknown, field: string): string[] {
  if (value === undefined) {
    return [];
  }

  if (!Array.isArray(value)) {
    throw new Error(`agent-identity field ${field} must be an array.`);
  }

  return value.map((item, index) => {
    if (typeof item !== "string" || !item.trim()) {
      throw new Error(`agent-identity field ${field}[${index}] must be a non-empty string.`);
    }

    return item.trim();
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseHttpsUrl(value: string, field: string): string {
  let parsed: URL;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error(`TXT field ${field} must be a valid URL.`);
  }

  if (parsed.protocol !== "https:") {
    throw new Error(`TXT field ${field} must use https.`);
  }

  return value;
}
