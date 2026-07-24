/**
 * Simple v1 license-key gating.
 *
 * Goals for v1:
 * - Fail clearly when the key is missing or invalid
 * - Keep validation local (no network required)
 * - Allow a documented development key for smoke tests
 *
 * Future: optional remote validation can plug into validateLicenseKey().
 */

import { promises as fs } from "node:fs";

/** Documented development key for local testing and CI. */
export const DEV_LICENSE_KEY = "smcp_dev_local_testing_key_v1";

/**
 * License keys must look like: smcp_<token>
 * Token: at least 16 characters of [A-Za-z0-9_-]
 */
const LICENSE_PATTERN = /^smcp_[A-Za-z0-9_-]{16,}$/;

export interface LicenseResult {
  valid: boolean;
  keySource: "env" | "file" | "none";
  reason?: string;
  isDevKey?: boolean;
}

/**
 * Resolve the license key from environment or optional file.
 *
 * Precedence:
 * 1. SECURE_MCP_LICENSE_KEY
 * 2. Contents of SECURE_MCP_LICENSE_FILE (single-line key)
 */
export async function resolveLicenseKey(): Promise<{
  key: string | null;
  source: "env" | "file" | "none";
}> {
  const envKey = process.env.SECURE_MCP_LICENSE_KEY?.trim();
  if (envKey) {
    return { key: envKey, source: "env" };
  }

  const filePath = process.env.SECURE_MCP_LICENSE_FILE?.trim();
  if (filePath) {
    try {
      const raw = await fs.readFile(filePath, "utf8");
      const key = raw
        .split("\n")
        .map((l) => l.trim())
        .find((l) => l && !l.startsWith("#"));
      if (key) {
        return { key, source: "file" };
      }
      return { key: null, source: "file" };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      throw new Error(
        `Could not read SECURE_MCP_LICENSE_FILE (${filePath}): ${message}`,
      );
    }
  }

  return { key: null, source: "none" };
}

/**
 * Validate a license key for v1 (local format + known dev key).
 * Production keys for a future paid tier can share the same format.
 */
export function validateLicenseKey(key: string | null | undefined): LicenseResult {
  if (!key || !key.trim()) {
    return {
      valid: false,
      keySource: "none",
      reason:
        "License key is missing. Set SECURE_MCP_LICENSE_KEY or SECURE_MCP_LICENSE_FILE. " +
        `For local development use: ${DEV_LICENSE_KEY}`,
    };
  }

  const trimmed = key.trim();
  if (!LICENSE_PATTERN.test(trimmed)) {
    return {
      valid: false,
      keySource: "env",
      reason:
        "License key format is invalid. Expected smcp_<token> with a token of at least 16 " +
        "alphanumeric/underscore/hyphen characters.",
    };
  }

  // v1: any well-formed key is accepted. A future release may call a remote validator.
  const isDevKey = trimmed === DEV_LICENSE_KEY;
  return {
    valid: true,
    keySource: "env",
    isDevKey,
  };
}

/**
 * Resolve + validate. Throws a clear Error if the license is not usable.
 * Call this once at process startup before accepting MCP connections.
 */
export async function requireValidLicense(): Promise<LicenseResult> {
  const { key, source } = await resolveLicenseKey();
  const result = validateLicenseKey(key);
  result.keySource = source;

  if (!result.valid) {
    const err = new Error(result.reason ?? "Invalid license");
    err.name = "LicenseError";
    throw err;
  }

  return result;
}
