/**
 * Local license-key gating.
 *
 * Goals for v1:
 * - Fail clearly when the key is missing or invalid
 * - Keep validation local (no network required)
 * - Allow a documented development key for smoke tests
 *
 * Production validation is cryptographic and does not require a network call.
 */

import { promises as fs } from "node:fs";
import { createPublicKey, verify as verifySignature } from "node:crypto";

/** Documented development key for local testing and CI. */
export const DEV_LICENSE_KEY = "smcp_dev_local_testing_key_v1";

/**
 * Development keys use the documented fixed value. Production keys are
 * signed opaque tokens: smcp_<payload>.<base64url-signature>. The payload and
 * signature are verified against the operator-configured public key.
 */
const SIGNED_LICENSE_PATTERN = /^smcp_[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}$/;

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
    } catch {
      throw new Error("Could not read the configured license file.");
    }
  }

  return { key: null, source: "none" };
}

/**
 * Validate a license key locally. The development key is intentionally gated
 * by DEV_MODE; production keys require a valid detached signature so that a
 * caller cannot authorize the server with an arbitrary smcp_ token.
 *
 * Dev keys are only accepted when SECURE_MCP_DEV_MODE=1 (for agents, local dev, CI).
 * When DEV_MODE + dev key: allow startup but the caller emits a clear warning on stderr.
 * Strict behavior is kept for production keys (and dev key without DEV_MODE).
 */
export function validateLicenseKey(key: string | null | undefined): LicenseResult {
  if (!key || !key.trim()) {
    return {
      valid: false,
      keySource: "none",
      reason:
        "License key is missing. Set SECURE_MCP_LICENSE_KEY or SECURE_MCP_LICENSE_FILE. " +
        `For local development use the documented dev key with SECURE_MCP_DEV_MODE=1: ${DEV_LICENSE_KEY}`,
    };
  }

  const trimmed = key.trim();
  if (trimmed === DEV_LICENSE_KEY) {
    const devMode = process.env.SECURE_MCP_DEV_MODE === "1";
    if (!devMode) {
      return {
        valid: false,
        keySource: "env",
        reason:
          `Development key ${DEV_LICENSE_KEY} is only permitted when SECURE_MCP_DEV_MODE=1 is set ` +
          "(for local development, agent testing, and CI smoke tests). " +
          "For production use, obtain a signed production license and do not set DEV_MODE.",
        isDevKey: true,
      };
    }
    return { valid: true, keySource: "env", isDevKey: true };
  }

  if (!SIGNED_LICENSE_PATTERN.test(trimmed)) {
    return {
      valid: false,
      keySource: "env",
      reason:
        "Production license format is invalid. Expected a signed smcp_<payload>.<signature> token.",
    };
  }

  const publicKey = process.env.SECURE_MCP_LICENSE_PUBLIC_KEY?.trim();
  if (!publicKey) {
    return {
      valid: false,
      keySource: "env",
      reason: "SECURE_MCP_LICENSE_PUBLIC_KEY must be configured for production license validation.",
    };
  }

  const separator = trimmed.lastIndexOf(".");
  const payload = trimmed.slice(0, separator);
  const encodedSignature = trimmed.slice(separator + 1);
  try {
    const publicKeyObject = createPublicKey(publicKey);
    const signature = Buffer.from(encodedSignature, "base64url");
    const valid = verifySignature(
      null,
      Buffer.from(payload, "utf8"),
      publicKeyObject,
      signature,
    );
    if (!valid) throw new Error("signature mismatch");
  } catch {
    return {
      valid: false,
      keySource: "env",
      reason: "Production license signature validation failed.",
    };
  }

  return { valid: true, keySource: "env", isDevKey: false };
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
