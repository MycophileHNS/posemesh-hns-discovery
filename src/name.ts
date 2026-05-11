export interface NameValidationResult {
  ok: boolean;
  normalizedName?: string;
  error?: string;
}

const HANDSHAKE_LABEL = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;
const MAX_DNS_NAME_LENGTH = 253;

export function normalizeName(name: string): string {
  return name.trim().replace(/\.$/, "");
}

export function validatePosemeshName(name: string): NameValidationResult {
  const normalizedName = normalizeName(name);

  if (!normalizedName) {
    return { ok: false, error: "Name is required." };
  }

  if (normalizedName.length > MAX_DNS_NAME_LENGTH) {
    return { ok: false, error: "Name is too long for DNS." };
  }

  const labels = normalizedName.split(".");
  const invalidLabel = labels.find((label) => !HANDSHAKE_LABEL.test(label));

  if (invalidLabel !== undefined) {
    return {
      ok: false,
      error: `Invalid Handshake label: ${invalidLabel || "(empty)"}`,
    };
  }

  if (!normalizedName.toLowerCase().endsWith(".posemesh")) {
    return {
      ok: false,
      error: "Name must be a subname ending in .posemesh.",
    };
  }

  return { ok: true, normalizedName };
}

export function assertValidPosemeshName(name: string): string {
  const result = validatePosemeshName(name);

  if (!result.ok || !result.normalizedName) {
    throw new Error(result.error ?? "Invalid .posemesh name.");
  }

  return result.normalizedName;
}
