import { createPublicKey } from "node:crypto";
import { discoveryError } from "./observability.ts";
import type { ManifestSignatureAlgorithm } from "./types.ts";

const HEX_PUBLIC_KEY = /^(?:0x)?[0-9a-f]+$/i;
const BASE64_PUBLIC_KEY = /^[A-Za-z0-9+/_-]+={0,2}$/;
const MAX_GENERIC_PUBLIC_KEY_BYTES = 1_024;

export function parsePublicKey(
  value: string,
  field: string,
  algorithm?: ManifestSignatureAlgorithm,
): string {
  const publicKey = value.trim();
  const bytes = decodePublicKey(publicKey, field);

  if (algorithm === "ed25519" && bytes.byteLength !== 32) {
    throw publicKeyError(`${field} must be a hex or base64 encoded 32-byte Ed25519 public key.`);
  }

  if (algorithm === "ecdsa-p256-sha256" && !isP256PublicKey(bytes)) {
    throw publicKeyError(`${field} must be a hex or base64 encoded valid P-256 public key.`);
  }

  if (!algorithm && !isGenericKnownPublicKey(bytes)) {
    throw publicKeyError(`${field} must be a hex or base64 encoded Ed25519 or P-256 public key.`);
  }

  if (bytes.byteLength > MAX_GENERIC_PUBLIC_KEY_BYTES) {
    throw publicKeyError(`${field} must not exceed ${MAX_GENERIC_PUBLIC_KEY_BYTES} bytes.`);
  }

  return publicKey;
}

export function isPublicKeyEncoding(value: string): boolean {
  try {
    decodePublicKey(value, "public key");
    return true;
  } catch {
    return false;
  }
}

export function decodePublicKey(value: string, field: string): Buffer {
  const publicKey = value.trim();

  if (!publicKey) {
    throw publicKeyError(`${field} must not be empty.`);
  }

  if (HEX_PUBLIC_KEY.test(publicKey)) {
    const hex = publicKey.replace(/^0x/i, "");

    if (hex.length === 0 || hex.length % 2 !== 0) {
      throw publicKeyError(`${field} must be valid even-length hex.`);
    }

    return Buffer.from(hex, "hex");
  }

  if (!BASE64_PUBLIC_KEY.test(publicKey)) {
    throw publicKeyError(`${field} must be hex, base64, or base64url.`);
  }

  const normalized = publicKey.replace(/-/g, "+").replace(/_/g, "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  const decoded = Buffer.from(padded, "base64");

  if (decoded.byteLength === 0) {
    throw publicKeyError(`${field} must decode to public key bytes.`);
  }

  return decoded;
}

function isP256PublicKey(bytes: Buffer): boolean {
  if (bytes.byteLength === 65 && bytes[0] === 0x04) {
    return true;
  }

  if (bytes.byteLength === 33 && (bytes[0] === 0x02 || bytes[0] === 0x03)) {
    return true;
  }

  try {
    createPublicKey({ key: bytes, format: "der", type: "spki" });
    return true;
  } catch {
    return false;
  }
}

function isGenericKnownPublicKey(bytes: Buffer): boolean {
  return bytes.byteLength === 32 || isP256PublicKey(bytes);
}

function publicKeyError(message: string): Error {
  return discoveryError("MANIFEST_PUBLIC_KEY_INVALID", message);
}
