import type { ParsedTxtRecords, PosemeshDiscoveryRecord } from "./types.ts";

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
  const capabilities = splitCsv(values.get("capabilities"));

  const result: PosemeshDiscoveryRecord = {
    kind: "posemesh",
    version: 1,
    raw: record,
    publicKeys: publicKey ? [publicKey] : [],
    capabilities,
  };

  if (manifestUrl) {
    result.manifestUrl = manifestUrl;
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

  const endpoint = optionalString(parsed.endpoint);
  const capabilities = optionalStringArray(parsed.capabilities);
  const publicKeys = extractPublicKeys(parsed);

  const result: PosemeshDiscoveryRecord = {
    kind: "agent-identity",
    version: 1,
    raw: record,
    publicKeys,
    capabilities,
  };

  if (endpoint) {
    result.manifestUrl = endpoint;
  }

  return result;
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
  const publicKeys = optionalStringArray(value.publicKeys);
  const publicKey = optionalString(value.publicKey);

  if (publicKey) {
    return [...publicKeys, publicKey];
  }

  return publicKeys;
}

function optionalString(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value.trim() : undefined;
}

function optionalStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }

  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
