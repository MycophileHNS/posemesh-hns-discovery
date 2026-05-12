import { createPublicKey, verify as verifySignature } from "node:crypto";
import type {
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

export interface VerifiedManifestEnvelope {
  envelope: SignedPosemeshManifestEnvelope;
  payloadText: string;
  verification: ManifestVerificationResult;
}

export function createManifestSigningBytes(payloadBytes: Uint8Array): Buffer {
  return Buffer.concat([MANIFEST_SIGNATURE_CONTEXT, Buffer.from(payloadBytes)]);
}

export function verifySignedManifestEnvelopeText(
  text: string,
  trustedKeys: ManifestVerificationKey[],
  now: Date,
): VerifiedManifestEnvelope {
  const parsed = JSON.parse(text) as unknown;
  const envelope = parseSignedManifestEnvelope(parsed);
  const payloadBytes = decodeKeyMaterial(envelope.payload, "manifest envelope payload");
  const signature = decodeKeyMaterial(envelope.signature, "manifest envelope signature");
  const signingBytes = createManifestSigningBytes(payloadBytes);
  const matchingKeys = selectMatchingKeys(envelope, trustedKeys);

  for (const key of matchingKeys) {
    if (verifyWithKey(envelope.algorithm, key.publicKey, signingBytes, signature)) {
      return {
        envelope,
        payloadText: payloadBytes.toString("utf8"),
        verification: {
          status: "verified",
          algorithm: envelope.algorithm,
          ...(envelope.keyId ? { keyId: envelope.keyId } : key.id ? { keyId: key.id } : {}),
          keySource: key.source,
          verifiedAt: now.toISOString(),
        },
      };
    }
  }

  throw new Error("Manifest signature verification failed for all trusted keys.");
}

export function parseSignedManifestEnvelope(value: unknown): SignedPosemeshManifestEnvelope {
  if (!isRecord(value)) {
    throw new Error("Signed manifest envelope must be a JSON object.");
  }

  if (value.version !== 1) {
    throw new Error("Signed manifest envelope version must be 1.");
  }

  if (
    !isNonEmptyString(value.payload) ||
    !isNonEmptyString(value.signature) ||
    !isNonEmptyString(value.algorithm)
  ) {
    throw new Error(
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

  throw new Error(`${field} must be ed25519 or ecdsa-p256-sha256.`);
}

function selectMatchingKeys(
  envelope: SignedPosemeshManifestEnvelope,
  trustedKeys: ManifestVerificationKey[],
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
    throw new Error(`No trusted ${envelope.algorithm} manifest verification key${keyId}.`);
  }

  return matchingKeys;
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
    throw new Error("Ed25519 public key must be 32 bytes.");
  }

  return createPublicKey({
    key: Buffer.concat([ED25519_SPKI_PREFIX, raw]),
    format: "der",
    type: "spki",
  });
}

function createP256PublicKey(publicKey: string): ReturnType<typeof createPublicKey> {
  const keyBytes = decodeKeyMaterial(publicKey, "P-256 public key");

  try {
    return createPublicKey({ key: keyBytes, format: "der", type: "spki" });
  } catch {
    if (keyBytes.byteLength === 65 && keyBytes[0] === 0x04) {
      return createPublicKey({
        key: Buffer.concat([P256_UNCOMPRESSED_SPKI_PREFIX, keyBytes]),
        format: "der",
        type: "spki",
      });
    }

    if (keyBytes.byteLength === 33 && (keyBytes[0] === 0x02 || keyBytes[0] === 0x03)) {
      return createPublicKey({
        key: Buffer.concat([P256_COMPRESSED_SPKI_PREFIX, keyBytes]),
        format: "der",
        type: "spki",
      });
    }
  }

  throw new Error("P-256 public key must be SPKI DER, compressed, or uncompressed point bytes.");
}

function decodeKeyMaterial(value: string, field: string): Buffer {
  const trimmed = value.trim();

  if (!trimmed) {
    throw new Error(`${field} must not be empty.`);
  }

  const hex = trimmed.replace(/^0x/i, "");

  if (/^[0-9a-f]+$/i.test(hex) && hex.length % 2 === 0) {
    return Buffer.from(hex, "hex");
  }

  if (!/^[A-Za-z0-9+/_-]+={0,2}$/.test(trimmed)) {
    throw new Error(`${field} must be hex, base64, or base64url.`);
  }

  const normalized = trimmed.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function requiredString(value: unknown, field: string): string {
  if (!isNonEmptyString(value)) {
    throw new Error(`${field} must be a non-empty string.`);
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
