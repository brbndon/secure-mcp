/**
 * Process-level configuration for secure-mcp.
 * All values can be overridden via environment variables.
 */

import path from "node:path";
import {
  HARD_MAX_DEPTH,
  HARD_MAX_FILE_BYTES,
  HARD_MAX_FILES,
  HARD_MAX_TOTAL_BYTES,
} from "./lib/filesystem.js";

export const SERVER_NAME = "secure-mcp";
export const SERVER_VERSION = "1.0.0";

export interface ServerConfig {
  name: string;
  version: string;
  /** Default max files tools will walk unless the caller overrides. */
  defaultMaxFiles: number;
  /** Max bytes read per file. */
  maxFileBytes: number;
  /** Max tree depth when walking. */
  maxDepth: number;
  /** Max aggregate bytes considered by a single filesystem walk. */
  maxTotalBytes?: number;
  /** Canonical-root allowlist. Undefined is retained for programmatic test configs. */
  allowedRoots?: string[];
}

export function loadConfig(): ServerConfig {
  const parsePositiveInt = (
    value: string | undefined,
    fallback: number,
    hardMaximum: number,
  ): number => {
    if (!value) return fallback;
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? Math.min(n, hardMaximum) : fallback;
  };

  const configuredRoots = (process.env.SECURE_MCP_ALLOWED_ROOTS ?? "")
    .split(path.delimiter)
    .map((root) => root.trim())
    .filter(Boolean);

  // Production configurations fail closed until an operator explicitly scopes
  // the filesystem roots. Dev mode keeps the existing local-test ergonomics.
  const allowedRoots =
    configuredRoots.length > 0 || process.env.SECURE_MCP_DEV_MODE !== "1"
      ? configuredRoots
      : undefined;

  return {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    defaultMaxFiles: parsePositiveInt(process.env.SECURE_MCP_MAX_FILES, 400, HARD_MAX_FILES),
    maxFileBytes: parsePositiveInt(
      process.env.SECURE_MCP_MAX_FILE_BYTES,
      256 * 1024,
      HARD_MAX_FILE_BYTES,
    ),
    maxDepth: parsePositiveInt(process.env.SECURE_MCP_MAX_DEPTH, 12, HARD_MAX_DEPTH),
    maxTotalBytes: parsePositiveInt(
      process.env.SECURE_MCP_MAX_TOTAL_BYTES,
      64 * 1024 * 1024,
      HARD_MAX_TOTAL_BYTES,
    ),
    allowedRoots,
  };
}
