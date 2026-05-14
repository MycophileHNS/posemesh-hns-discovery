import { decodePublicKey, parsePublicKey } from "./public-keys.ts";
import { parseManifestSignatureAlgorithm } from "./security.ts";
import { createWarning, getErrorCode, getErrorMessage, logDebug, logWarn } from "./observability.ts";
import { parseStrictUtcTimestamp } from "./timestamps.ts";
import type {
  DiscoveryLogger,
  LoggerRedactionOptions,
  ManifestSignatureAlgorithm,
  ManifestVerificationKey,
  ParsedTxtRecords,
  ParserOptions,
  ParserLimits,
  PosemeshDiscoveryRecord,
} from "./types.ts";

const POSEMESH_PREFIX = "posemesh:v1";
const AGENT_IDENTITY_PREFIX = "agent-identity:v1=";

interface ResolvedParserLimits {
  maxTxtRecords: number;
  maxTxtRecordBytes: number;
  maxTotalTxtBytes: number;
  maxFieldsPerRecord: number;
  maxFieldNameBytes: number;
  maxFieldValueBytes: number;
  maxCapabilities: number;
  maxPublicKeys: number;
  maxAgentIdentityBytes: number;
}

type ParserInput = ParserLimits | ParserOptions;

interface ResolvedParserInput {
  limits: ParserLimits;
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

const DEFAULT_PARSER_LIMITS: ResolvedParserLimits = {
  maxTxtRecords: 32,
  maxTxtRecordBytes: 4_096,
  maxTotalTxtBytes: 64 * 1024,
  maxFieldsPerRecord: 32,
  maxFieldNameBytes: 64,
  maxFieldValueBytes: 4_096,
  maxCapabilities: 64,
  maxPublicKeys: 16,
  maxAgentIdentityBytes: 8_192,
};

export function parseTxtRecords(
  txtRecords: string[],
  input: ParserInput = {},
): ParsedTxtRecords {
  const parserOptions = resolveParserInput(input);
  const resolvedLimits = resolveParserLimits(parserOptions.limits);
  logDebug(
    parserOptions.logger,
    "Parsing TXT records",
    { recordCount: txtRecords.length },
    parserOptions.redaction,
  );
  enforceMaxCount(txtRecords.length, resolvedLimits.maxTxtRecords, "TXT records");
  enforceMaxBytes(
    txtRecords.reduce((total, record) => total + byteLength(record), 0),
    resolvedLimits.maxTotalTxtBytes,
    "total TXT records",
  );

  const parsed: PosemeshDiscoveryRecord[] = [];
  const warnings: ParsedTxtRecords["warnings"] = [];

  for (const record of txtRecords) {
    try {
      const discoveryRecord = parseTxtRecord(record, resolvedLimits);

      if (discoveryRecord) {
        parsed.push(discoveryRecord);
      }
    } catch (error) {
      const warning = createWarning({
        source: "txt",
        record,
        code: getErrorCode(error, "TXT_PARSE_ERROR"),
        message: getErrorMessage(error, "Unknown TXT parsing error."),
      });
      warnings.push(warning);
      logWarn(
        parserOptions.logger,
        "TXT record parse warning",
        {
          code: warning.code ?? "TXT_PARSE_ERROR",
          message: warning.message,
          recordBytes: byteLength(record),
        },
        parserOptions.redaction,
      );
    }
  }

  logDebug(
    parserOptions.logger,
    "Finished parsing TXT records",
    { recordCount: parsed.length, warningCount: warnings.length },
    parserOptions.redaction,
  );

  return { records: parsed, warnings };
}

export function parseTxtRecord(
  record: string,
  input: ParserInput = {},
): PosemeshDiscoveryRecord | undefined {
  const resolvedLimits = resolveParserLimits(resolveParserInput(input).limits);
  enforceMaxBytes(byteLength(record), resolvedLimits.maxTxtRecordBytes, "TXT record");
  const trimmed = record.trim();

  if (trimmed.startsWith(POSEMESH_PREFIX)) {
    return parsePosemeshTxt(trimmed, resolvedLimits);
  }

  if (trimmed.startsWith(AGENT_IDENTITY_PREFIX)) {
    return parseAgentIdentityTxt(trimmed, resolvedLimits);
  }

  return undefined;
}

export function parsePosemeshTxt(
  record: string,
  input: ParserInput = {},
): PosemeshDiscoveryRecord {
  const resolvedLimits = resolveParserLimits(resolveParserInput(input).limits);
  enforceMaxBytes(byteLength(record), resolvedLimits.maxTxtRecordBytes, "posemesh TXT record");
  const [prefix, ...parts] = record.split(";").map((part) => part.trim());

  if (prefix !== POSEMESH_PREFIX) {
    throw new Error("Unsupported posemesh TXT version.");
  }

  enforceMaxCount(parts.filter(Boolean).length, resolvedLimits.maxFieldsPerRecord, "TXT fields");
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

    enforceMaxBytes(byteLength(key), resolvedLimits.maxFieldNameBytes, "TXT field name");
    enforceMaxBytes(byteLength(value), resolvedLimits.maxFieldValueBytes, `TXT field ${key}`);

    if (values.has(key)) {
      throw new Error(`Duplicate posemesh TXT field: ${key}`);
    }

    values.set(key, value);
  }

  const manifestUrl = values.get("manifest");
  const publicKey = values.get("publicKey");
  const publicKeysCsv = splitCsv(values.get("publicKeys"));
  const keyId = values.get("keyId");
  const algorithm = parseOptionalAlgorithm(values.get("alg"));
  const notBefore = parseOptionalTimestamp(values.get("notBefore"), "notBefore");
  const notAfter = parseOptionalTimestamp(values.get("notAfter"), "notAfter");
  const capabilities = limitArray(
    splitCsv(values.get("capabilities")),
    resolvedLimits.maxCapabilities,
    "TXT capabilities",
  );
  const publicKeys = uniqueStrings([
    ...(publicKey ? [parsePublicKey(publicKey, "TXT field publicKey", algorithm)] : []),
    ...publicKeysCsv.map((key, index) =>
      parsePublicKey(key, `TXT field publicKeys[${index}]`, algorithm),
    ),
  ]);
  enforceMaxCount(publicKeys.length, resolvedLimits.maxPublicKeys, "TXT public keys");

  const result: PosemeshDiscoveryRecord = {
    kind: "posemesh",
    version: 1,
    raw: record,
    publicKeys,
    verificationKeys: createVerificationKeys(publicKeys, algorithm, keyId, {
      ...(notBefore ? { notBefore } : {}),
      ...(notAfter ? { notAfter } : {}),
    }),
    capabilities,
  };

  if (manifestUrl) {
    result.manifestUrl = parseHttpsUrl(manifestUrl, "manifest");
  }

  return result;
}

export function parseAgentIdentityTxt(
  record: string,
  input: ParserInput = {},
): PosemeshDiscoveryRecord {
  const resolvedLimits = resolveParserLimits(resolveParserInput(input).limits);
  enforceMaxBytes(
    byteLength(record),
    resolvedLimits.maxAgentIdentityBytes,
    "agent-identity TXT record",
  );
  const jsonText = record.slice(AGENT_IDENTITY_PREFIX.length).trim();
  const parsed = JSON.parse(jsonText) as unknown;

  if (!isRecord(parsed)) {
    throw new Error("agent-identity payload must be a JSON object.");
  }

  if (parsed.version !== 1) {
    throw new Error("Unsupported agent-identity version.");
  }

  const endpoint = requiredString(parsed.endpoint, "endpoint", resolvedLimits);
  const capabilities = limitArray(
    optionalStringArray(parsed.capabilities, "capabilities", resolvedLimits),
    resolvedLimits.maxCapabilities,
    "agent-identity capabilities",
  );
  const publicKeys = extractPublicKeys(parsed, resolvedLimits);
  enforceMaxCount(publicKeys.length, resolvedLimits.maxPublicKeys, "agent-identity public keys");

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
  algorithm: ManifestSignatureAlgorithm | undefined,
  keyId: string | undefined,
  validity: Pick<ManifestVerificationKey, "notBefore" | "notAfter">,
): ManifestVerificationKey[] {
  return publicKeys.map((publicKey) => ({
    ...(keyId ? { id: keyId } : {}),
    algorithm: algorithm ?? inferLegacyTxtKeyAlgorithm(publicKey),
    publicKey,
    source: "txt",
    ...validity,
  }));
}

function inferLegacyTxtKeyAlgorithm(publicKey: string): ManifestSignatureAlgorithm {
  const bytes = decodePublicKey(publicKey, "TXT public key");
  return bytes.byteLength === 32 ? "ed25519" : "ecdsa-p256-sha256";
}

function parseOptionalAlgorithm(value: string | undefined): ManifestSignatureAlgorithm | undefined {
  if (!value) {
    return undefined;
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

function parseOptionalTimestamp(value: string | undefined, field: string): string | undefined {
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();

  if (!parseStrictUtcTimestamp(trimmed)) {
    throw new Error(`TXT field ${field} must be a valid ISO-8601 UTC timestamp.`);
  }

  return trimmed;
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)];
}

function extractPublicKeys(
  value: Record<string, unknown>,
  limits: ResolvedParserLimits,
): string[] {
  const publicKeys = optionalStringArray(value.publicKeys, "publicKeys", limits);
  const publicKey = optionalString(value.publicKey, "publicKey", limits);
  const parsedPublicKeys = publicKeys.map((key, index) =>
    parsePublicKey(key, `agent-identity field publicKeys[${index}]`),
  );

  if (publicKey) {
    return [...parsedPublicKeys, parsePublicKey(publicKey, "agent-identity field publicKey")];
  }

  return parsedPublicKeys;
}

function requiredString(value: unknown, field: string, limits: ResolvedParserLimits): string {
  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`agent-identity field ${field} must be a non-empty string.`);
  }

  const trimmed = value.trim();
  enforceMaxBytes(byteLength(trimmed), limits.maxFieldValueBytes, `agent-identity field ${field}`);
  return trimmed;
}

function optionalString(
  value: unknown,
  field: string,
  limits: ResolvedParserLimits,
): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  if (typeof value !== "string" || !value.trim()) {
    throw new Error(`agent-identity field ${field} must be a non-empty string.`);
  }

  const trimmed = value.trim();
  enforceMaxBytes(byteLength(trimmed), limits.maxFieldValueBytes, `agent-identity field ${field}`);
  return trimmed;
}

function optionalStringArray(
  value: unknown,
  field: string,
  limits: ResolvedParserLimits,
): string[] {
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

    const trimmed = item.trim();
    enforceMaxBytes(
      byteLength(trimmed),
      limits.maxFieldValueBytes,
      `agent-identity field ${field}[${index}]`,
    );
    return trimmed;
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

  if (parsed.username || parsed.password) {
    throw new Error(`TXT field ${field} must not include username or password.`);
  }

  return value;
}

function resolveParserLimits(limits: ParserLimits): ResolvedParserLimits {
  return {
    maxTxtRecords: readPositiveIntegerLimit(limits.maxTxtRecords, DEFAULT_PARSER_LIMITS.maxTxtRecords, "maxTxtRecords"),
    maxTxtRecordBytes: readPositiveIntegerLimit(limits.maxTxtRecordBytes, DEFAULT_PARSER_LIMITS.maxTxtRecordBytes, "maxTxtRecordBytes"),
    maxTotalTxtBytes: readPositiveIntegerLimit(limits.maxTotalTxtBytes, DEFAULT_PARSER_LIMITS.maxTotalTxtBytes, "maxTotalTxtBytes"),
    maxFieldsPerRecord: readPositiveIntegerLimit(limits.maxFieldsPerRecord, DEFAULT_PARSER_LIMITS.maxFieldsPerRecord, "maxFieldsPerRecord"),
    maxFieldNameBytes: readPositiveIntegerLimit(limits.maxFieldNameBytes, DEFAULT_PARSER_LIMITS.maxFieldNameBytes, "maxFieldNameBytes"),
    maxFieldValueBytes: readPositiveIntegerLimit(limits.maxFieldValueBytes, DEFAULT_PARSER_LIMITS.maxFieldValueBytes, "maxFieldValueBytes"),
    maxCapabilities: readPositiveIntegerLimit(limits.maxCapabilities, DEFAULT_PARSER_LIMITS.maxCapabilities, "maxCapabilities"),
    maxPublicKeys: readPositiveIntegerLimit(limits.maxPublicKeys, DEFAULT_PARSER_LIMITS.maxPublicKeys, "maxPublicKeys"),
    maxAgentIdentityBytes: readPositiveIntegerLimit(limits.maxAgentIdentityBytes, DEFAULT_PARSER_LIMITS.maxAgentIdentityBytes, "maxAgentIdentityBytes"),
  };
}

function resolveParserInput(input: ParserInput): ResolvedParserInput {
  if ("limits" in input || "logger" in input || "redaction" in input) {
    return {
      limits: input.limits ?? {},
      ...(input.logger ? { logger: input.logger } : {}),
      ...(input.redaction ? { redaction: input.redaction } : {}),
    };
  }

  return { limits: input as ParserLimits };
}

function readPositiveIntegerLimit(
  value: number | undefined,
  fallback: number,
  field: string,
): number {
  if (value === undefined) {
    return fallback;
  }

  if (!Number.isInteger(value) || value < 1) {
    throw discoveryLimitError(`Parser limit ${field} must be a positive integer.`);
  }

  return value;
}

function enforceMaxCount(count: number, max: number, field: string): void {
  if (count > max) {
    throw discoveryLimitError(`${field} exceeds limit ${max}.`);
  }
}

function enforceMaxBytes(bytes: number, max: number, field: string): void {
  if (bytes > max) {
    throw discoveryLimitError(`${field} exceeds ${max} bytes.`);
  }
}

function limitArray<T>(items: T[], max: number, field: string): T[] {
  enforceMaxCount(items.length, max, field);
  return items;
}

function byteLength(value: string): number {
  return Buffer.byteLength(value, "utf8");
}

function discoveryLimitError(message: string): Error {
  return Object.assign(new Error(message), { code: "TXT_LIMIT_EXCEEDED" as const });
}
