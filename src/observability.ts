import type {
  DiscoveryErrorCode,
  DiscoveryLogFields,
  DiscoveryLogValue,
  DiscoveryLogger,
  LoggerRedactionOptions,
  ParseWarning,
} from "./types.ts";

const DEFAULT_REDACT_KEYS = new Set(
  [
    "privateKey",
    "secret",
    "token",
    "authorization",
    "signature",
    "payload",
    "publicKey",
    "publicKeys",
    "trustedKeys",
    "tlsPins",
    "certificateAssociationData",
    "data",
  ].map((key) => key.toLowerCase()),
);

export class DiscoveryError extends Error {
  readonly code: DiscoveryErrorCode;
  readonly details?: DiscoveryLogFields;

  constructor(
    code: DiscoveryErrorCode,
    message: string,
    details?: DiscoveryLogFields,
    cause?: unknown,
  ) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = "DiscoveryError";
    this.code = code;

    if (details) {
      this.details = details;
    }
  }
}

export function discoveryError(
  code: DiscoveryErrorCode,
  message: string,
  details?: DiscoveryLogFields,
  cause?: unknown,
): DiscoveryError {
  return new DiscoveryError(code, message, details, cause);
}

export function getErrorCode(
  error: unknown,
  fallback: DiscoveryErrorCode = "UNKNOWN_ERROR",
): DiscoveryErrorCode {
  if (error instanceof DiscoveryError) {
    return error.code;
  }

  if (error && typeof error === "object" && "code" in error) {
    const code = String(error.code);

    if (isDiscoveryErrorCode(code)) {
      return code;
    }
  }

  return fallback;
}

export function getErrorMessage(error: unknown, fallback = "Unknown error."): string {
  return error instanceof Error ? error.message : fallback;
}

export function createWarning(input: {
  source: ParseWarning["source"];
  message: string;
  code?: DiscoveryErrorCode;
  record?: string;
  url?: string;
}): ParseWarning {
  return {
    source: input.source,
    ...(input.record ? { record: input.record } : {}),
    ...(input.url ? { url: input.url } : {}),
    ...(input.code ? { code: input.code } : {}),
    message: input.message,
  };
}

export function logDebug(
  logger: DiscoveryLogger | undefined,
  message: string,
  fields?: DiscoveryLogFields,
  redaction?: LoggerRedactionOptions,
): void {
  log(logger, "debug", message, fields, redaction);
}

export function logInfo(
  logger: DiscoveryLogger | undefined,
  message: string,
  fields?: DiscoveryLogFields,
  redaction?: LoggerRedactionOptions,
): void {
  log(logger, "info", message, fields, redaction);
}

export function logWarn(
  logger: DiscoveryLogger | undefined,
  message: string,
  fields?: DiscoveryLogFields,
  redaction?: LoggerRedactionOptions,
): void {
  log(logger, "warn", message, fields, redaction);
}

export function logError(
  logger: DiscoveryLogger | undefined,
  message: string,
  fields?: DiscoveryLogFields,
  redaction?: LoggerRedactionOptions,
): void {
  log(logger, "error", message, fields, redaction);
}

export function errorLogFields(
  error: unknown,
  fallback: DiscoveryErrorCode = "UNKNOWN_ERROR",
): DiscoveryLogFields {
  return {
    code: getErrorCode(error, fallback),
    message: getErrorMessage(error),
  };
}

function log(
  logger: DiscoveryLogger | undefined,
  level: keyof DiscoveryLogger,
  message: string,
  fields: DiscoveryLogFields | undefined,
  redaction: LoggerRedactionOptions | undefined,
): void {
  if (!logger) {
    return;
  }

  try {
    logger[level](message, fields ? redactFields(fields, redaction) : undefined);
  } catch {
    // A caller-provided logger should never change discovery behavior.
  }
}

function redactFields(
  fields: DiscoveryLogFields,
  redaction: LoggerRedactionOptions | undefined,
): DiscoveryLogFields {
  const configuredKeys = new Set(
    (redaction?.redactKeys ?? []).map((key) => key.trim().toLowerCase()).filter(Boolean),
  );
  const replacement = redaction?.replacement ?? "[redacted]";

  return redactObject(fields, configuredKeys, replacement) as DiscoveryLogFields;
}

function redactObject(
  value: DiscoveryLogValue,
  configuredKeys: Set<string>,
  replacement: string,
  key?: string,
): DiscoveryLogValue {
  if (key && shouldRedactKey(key, configuredKeys)) {
    return replacement;
  }

  if (Array.isArray(value)) {
    return value.map((item) => redactObject(item, configuredKeys, replacement));
  }

  if (value && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([entryKey, entryValue]) => [
        entryKey,
        redactObject(entryValue, configuredKeys, replacement, entryKey),
      ]),
    );
  }

  return value;
}

function shouldRedactKey(key: string, configuredKeys: Set<string>): boolean {
  const normalized = key.toLowerCase();
  return DEFAULT_REDACT_KEYS.has(normalized) || configuredKeys.has(normalized);
}

function isDiscoveryErrorCode(value: string): value is DiscoveryErrorCode {
  return DISCOVERY_ERROR_CODES.has(value as DiscoveryErrorCode);
}

const DISCOVERY_ERROR_CODES = new Set<DiscoveryErrorCode>([
  "UNKNOWN_ERROR",
  "INVALID_POSEMESH_NAME",
  "TXT_LOOKUP_ERROR",
  "TXT_NO_RECORDS",
  "TXT_NO_COMPATIBLE_RECORDS",
  "TXT_PARSE_ERROR",
  "TXT_LIMIT_EXCEEDED",
  "TXT_AMBIGUOUS_MANIFEST",
  "RESOLVER_LOOKUP_ERROR",
  "RESOLVER_CONSENSUS_FAILED",
  "RESOLVER_UNSUPPORTED",
  "MANIFEST_FETCH_ERROR",
  "MANIFEST_URL_INVALID",
  "MANIFEST_URL_UNSAFE",
  "MANIFEST_HTTP_ERROR",
  "MANIFEST_REDIRECT_REJECTED",
  "MANIFEST_CONTENT_TYPE_INVALID",
  "MANIFEST_TOO_LARGE",
  "MANIFEST_TIMEOUT",
  "MANIFEST_TLS_PIN_MISMATCH",
  "MANIFEST_PARSE_ERROR",
  "MANIFEST_SCHEMA_INVALID",
  "MANIFEST_SIGNATURE_REQUIRED",
  "MANIFEST_SIGNATURE_INVALID",
  "MANIFEST_KEY_REQUIRED",
  "MANIFEST_KEY_INACTIVE",
  "MANIFEST_REPLAY_INVALID",
  "MANIFEST_BINDING_MISMATCH",
  "MANIFEST_PUBLIC_KEY_INVALID",
  "DANE_TLSA_LOOKUP_ERROR",
  "DANE_TLSA_REQUIRED",
  "DANE_TLSA_MISMATCH",
]);
