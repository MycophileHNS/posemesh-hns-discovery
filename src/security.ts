import { createPublicKey, verify as verifySignature } from "node:crypto";
import type { KeyObject } from "node:crypto";
import { discoveryError, logDebug } from "./observability.ts";
import { parseStrictUtcTimestamp } from "./timestamps.ts";
import type {
  DiscoveryLogger,
  LoggerRedactionOptions,
  ManifestSignatureAlgorithm,
  ManifestVerificationKey,
  ManifestVerificationResult,
  SignedPosemeshManifestEnvelope,
} from "./types.ts";

const MANIFEST_SIGNATURE_CONTEXT = Buffer.from("posemesh-manifest:v1\n", "utf8");
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const P256_UNCOMPRESSED_SPKI_PREFIX = Buffer.from(
  "3059301306072a8648ce3d020106082a8648ce3d030107034200",
  "hex",
);
const P256_COMPRESSED_SPKI_PREFIX = Buffer.from(
  "3039301306072a8648ce3d020106082a8648ce3d030107032200",
  "hex",
);
const P256_CURVE_NAMES = new Set(["P-256", "prime256v1", "secp256r1"]);

export interface VerifiedManifestEnvelope {
  envelope: SignedPosemeshManifestEnvelope;
  payloadText: string;
  verification: ManifestVerificationResult;
}

interface VerificationObservabilityOptions {
  logger?: DiscoveryLogger;
  redaction?: LoggerRedactionOptions;
}

export function createManifestSigningBytes(payloadBytes: Uint8Array): Buffer {
  return Buffer.concat([MANIFEST_SIGNATURE_CONTEXT, Buffer.from(payloadBytes)]);
}

export function verifySignedManifestEnvelopeText(
  text: string,
  trustedKeys: ManifestVerificationKey[],
  now: Date,
  observability: VerificationObservabilityOptions = {},
): VerifiedManifestEnvelope {
  const parsed = JSON.parse(text) as unknown;
  const envelope = parseSignedManifestEnvelope(parsed);
  const payloadBytes = decodeKeyMaterial(envelope.payload, "manifest envelope payload");
  const signature = decodeKeyMaterial(envelope.signature, "manifest envelope signature");
  const signingBytes = createManifestSigningBytes(payloadBytes);
  const matchingKeys = selectMatchingKeys(envelope, trustedKeys, now);
  logDebug(
    observability.logger,
    "Verifying signed manifest envelope",
    {
      algorithm: envelope.algorithm,
      keyId: envelope.keyId ?? "",
      candidateKeyCount: matchingKeys.length,
    },
    observability.redaction,
  );

  for (const key of matchingKeys) {
    if (verifyWithKey(envelope.algorithm, key.publicKey, signingBytes, signature)) {
      logDebug(
        observability.logger,
        "Manifest signature verified",
        {
          algorithm: envelope.algorithm,
          keyId: envelope.keyId ?? key.id ?? "",
          keySource: key.source,
        },
        observability.redaction,
      );
      return {
        envelope,
        payloadText: payloadBytes.toString("utf8"),
        verification: {
          status: "verified",
          algorithm: envelope.algorithm,
          ...(envelope.keyId ? { keyId: envelope.keyId } : key.id ? { keyId: key.id } : {}),
          keySource: key.source,
          ...(key.notBefore ? { keyNotBefore: key.notBefore } : {}),
          ...(key.notAfter ? { keyNotAfter: key.notAfter } : {}),
          verifiedAt: now.toISOString(),
        },
      };
    }
  }

  throw discoveryError(
    "MANIFEST_SIGNATURE_INVALID",
    "Manifest signature verification failed for all trusted keys.",
    {
      algorithm: envelope.algorithm,
      keyId: envelope.keyId ?? "",
      candidateKeyCount: matchingKeys.length,
    },
  );
}

export function parseSignedManifestEnvelope(value: unknown): SignedPosemeshManifestEnvelope {
  if (!isRecord(value)) {
    throw discoveryError("MANIFEST_SIGNATURE_REQUIRED", "Signed manifest envelope must be a JSON object.");
  }

  if (value.version !== 1) {
    throw discoveryError("MANIFEST_SIGNATURE_INVALID", "Signed manifest envelope version must be 1.");
  }

  if (
    !isNonEmptyString(value.payload) ||
    !isNonEmptyString(value.signature) ||
    !isNonEmptyString(value.algorithm)
  ) {
    throw discoveryError(
      "MANIFEST_SIGNATURE_REQUIRED",
      "Strict manifest verification requires a signed manifest envelope with payload, signature, and algorithm.",
    );
  }

  const payload = requiredString(value.payload, "manifest envelope payload");
  const signature = requiredString(value.signature, "manifest envelope signature");
  const algorithm = parseManifestSignatureAlgorithm(value.algorithm, "manifest envelope algorithm");
  const keyId = optionalString(value.keyId, "manifest envelope keyId");

  return {
    version: 1,
    payload,
    signature,
    algorithm,
    ...(keyId ? { keyId } : {}),
  };
}

export function parseManifestSignatureAlgorithm(
  value: unknown,
  field: string,
): ManifestSignatureAlgorithm {
  if (value === "ed25519" || value === "ecdsa-p256-sha256") {
    return value;
  }

  throw discoveryError("MANIFEST_SIGNATURE_INVALID", `${field} must be ed25519 or ecdsa-p256-sha256.`);
}

function selectMatchingKeys(
  envelope: SignedPosemeshManifestEnvelope,
  trustedKeys: ManifestVerificationKey[],
  now: Date,
): ManifestVerificationKey[] {
  const matchingKeys = trustedKeys.filter((key) => {
    if (key.algorithm !== envelope.algorithm) {
      return false;
    }

    if (envelope.keyId && key.id !== envelope.keyId) {
      return false;
    }

    return true;
  });

  if (matchingKeys.length === 0) {
    const keyId = envelope.keyId ? ` with keyId ${envelope.keyId}` : "";
    throw discoveryError(
      "MANIFEST_KEY_REQUIRED",
      `No trusted ${envelope.algorithm} manifest verification key${keyId}.`,
      { algorithm: envelope.algorithm, keyId: envelope.keyId ?? "" },
    );
  }

  const activeKeys = matchingKeys.filter((key) => isVerificationKeyActive(key, now));

  if (activeKeys.length === 0) {
    const keyId = envelope.keyId ? ` with keyId ${envelope.keyId}` : "";
    throw discoveryError(
      "MANIFEST_KEY_INACTIVE",
      `No currently valid ${envelope.algorithm} manifest verification key${keyId}.`,
      { algorithm: envelope.algorithm, keyId: envelope.keyId ?? "" },
    );
  }

  return activeKeys;
}

function isVerificationKeyActive(key: ManifestVerificationKey, now: Date): boolean {
  const notBefore = parseOptionalKeyTimestamp(key.notBefore, "notBefore");
  const notAfter = parseOptionalKeyTimestamp(key.notAfter, "notAfter");

  if (notBefore && notAfter && notAfter.getTime() <= notBefore.getTime()) {
    throw discoveryError(
      "MANIFEST_KEY_INACTIVE",
      "Manifest verification key notAfter must be after notBefore.",
    );
  }

  if (notBefore && notBefore.getTime() > now.getTime()) {
    return false;
  }

  if (notAfter && notAfter.getTime() < now.getTime()) {
    return false;
  }

  return true;
}

function parseOptionalKeyTimestamp(value: string | undefined, field: string): Date | undefined {
  if (!value) {
    return undefined;
  }

  const parsed = parseStrictUtcTimestamp(value);

  if (!parsed) {
    throw discoveryError(
      "MANIFEST_KEY_INACTIVE",
      `Manifest verification key ${field} must be a valid ISO-8601 UTC timestamp.`,
      { field },
    );
  }

  return parsed;
}

function verifyWithKey(
  algorithm: ManifestSignatureAlgorithm,
  publicKey: string,
  signingBytes: Buffer,
  signature: Buffer,
): boolean {
  try {
    if (algorithm === "ed25519") {
      const key = createEd25519PublicKey(publicKey);
      return verifySignature(null, signingBytes, key, signature);
    }

    const key = createP256PublicKey(publicKey);
    return verifySignature("sha256", signingBytes, key, signature);
  } catch {
    return false;
  }
}

function createEd25519PublicKey(publicKey: string): ReturnType<typeof createPublicKey> {
  const raw = decodeKeyMaterial(publicKey, "Ed25519 public key");

  if (raw.byteLength !== 32) {
    throw discoveryError("MANIFEST_PUBLIC_KEY_INVALID", "Ed25519 public key must be 32 bytes.");
  }

  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function createP256PublicKey(publicKey: string): ReturnType<typeof createPublicKey> {
  const keyBytes = decodeKeyMaterial(publicKey, "P-256 public key");
  const spkiKey = tryCreateSpkiPublicKey(keyBytes);

  if (spkiKey) {
    return assertP256PublicKey(spkiKey);
  }

  if (keyBytes.byteLength === 65 && keyBytes[0] === 0x04) {
    return assertP256PublicKey(
      createPublicKey({
        key: Buffer.concat([P256_UNCOMPRESSED_SPKI_PREFIX, keyBytes]),
        format: "der",
        type: "spki",
      }),
    );
  }

  if (keyBytes.byteLength === 33 && (keyBytes[0] === 0x02 || keyBytes[0] === 0x03)) {
    return assertP256PublicKey(
      createPublicKey({
        key: Buffer.concat([P256_COMPRESSED_SPKI_PREFIX, keyBytes]),
        format: "der",
        type: "spki",
      }),
    );
  }

  throw discoveryError(
    "MANIFEST_PUBLIC_KEY_INVALID",
    "P-256 public key must be SPKI DER, compressed, or uncompressed point bytes.",
  );
}

function tryCreateSpkiPublicKey(keyBytes: Buffer): KeyObject | undefined {
  try {
    return createPublicKey({ key: keyBytes, format: "der", type: "spki" });
  } catch {
    return undefined;
  }
}

function assertP256PublicKey(key: KeyObject): KeyObject {
  const namedCurve = key.asymmetricKeyDetails?.namedCurve;

  if (key.asymmetricKeyType !== "ec" || !namedCurve || !P256_CURVE_NAMES.has(namedCurve)) {
    throw discoveryError(
      "MANIFEST_PUBLIC_KEY_INVALID",
      "P-256 public key must be an EC public key on the P-256 curve.",
      {
        keyType: key.asymmetricKeyType ?? "",
        namedCurve: namedCurve ?? "",
      },
    );
  }

  return key;
}

function decodeKeyMaterial(value: string, field: string): Buffer {
  const trimmed = value.trim();

  if (!trimmed) {
    throw discoveryError("MANIFEST_SIGNATURE_INVALID", `${field} must not be empty.`);
  }

  const hex = trimmed.replace(/^0x/i, "");

  if (/^[0-9a-f]+$/i.test(hex) && hex.length % 2 === 0) {
    return Buffer.from(hex, "hex");
  }

  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    throw discoveryError("MANIFEST_SIGNATURE_INVALID", `${field} must be hex, base64, or base64url.`);
  }

  const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function requiredString(value: unknown, field: string): string {
  if (!isNonEmptyString(value)) {
    throw discoveryError("MANIFEST_SIGNATURE_INVALID", `${field} must be a non-empty string.`);
  }

  return value.trim();
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined) {
    return undefined;
  }

  return requiredString(value, field);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === "string" && value.trim().length > 0;
}
