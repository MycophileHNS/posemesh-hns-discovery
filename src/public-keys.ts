const HEX_PUBLIC_KEY = /^(?:0x)?[0-9a-f]+$/i;
const BASE64_PUBLIC_KEY = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

export function parsePublicKey(value: string, field: string): string {
  const publicKey = value.trim();

  if (!isPublicKeyEncoding(publicKey)) {
    throw new Error(`${field} must be hex or base64.`);
  }

  return publicKey;
}

export function isPublicKeyEncoding(value: string): boolean {
  const publicKey = value.trim();

  if (!publicKey) {
    return false;
  }

  if (HEX_PUBLIC_KEY.test(publicKey)) {
    const hex = publicKey.replace(/^0x/i, "");
    return hex.length > 0 && hex.length % 2 === 0;
  }

  return publicKey.length % 4 === 0 && BASE64_PUBLIC_KEY.test(publicKey);
}
