export interface ValidatePosemeshNameOptions {
  allowAnyHandshakeName?: boolean;
}

export interface NameValidationResult {
  ok: boolean;
  normalizedName?: string;
  error?: string;
}

const HANDSHAKE_LABEL = /^[a-z0-9][a-z0-9-]{0,62}$/i;

export function normalizeName(name: string): string {
  return name.trim().replace(/\.$/, "");
}

export function validatePosemeshName(
  name: string,
  options: ValidatePosemeshNameOptions = {},
): NameValidationResult {
  const normalizedName = normalizeName(name);

  if (!normalizedName) {
    return { ok: false, error: "Name is required." };
  }

  const labels = normalizedName.split(".");
  const invalidLabel = labels.find((label) => !HANDSHAKE_LABEL.test(label));

  if (invalidLabel) {
    return {
      ok: false,
      error: `Invalid Handshake label: ${invalidLabel}`,
    };
  }

  if (!options.allowAnyHandshakeName && !normalizedName.toLowerCase().endsWith(".posemesh")) {
    return {
      ok: false,
      error: "Name must end in .posemesh unless allowAnyHandshakeName is true.",
    };
  }

  return { ok: true, normalizedName };
}

export function assertValidPosemeshName(
  name: string,
  options: ValidatePosemeshNameOptions = {},
): string {
  const result = validatePosemeshName(name, options);

  if (!result.ok || !result.normalizedName) {
    throw new Error(result.error ?? "Invalid .posemesh name.");
  }

  return result.normalizedName;
}
