/**
 * Process-level configuration for secure-mcp.
 * All values can be overridden via environment variables.
 */

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
}

export function loadConfig(): ServerConfig {
  const parsePositiveInt = (value: string | undefined, fallback: number): number => {
    if (!value) return fallback;
    const n = Number.parseInt(value, 10);
    return Number.isFinite(n) && n > 0 ? n : fallback;
  };

  return {
    name: SERVER_NAME,
    version: SERVER_VERSION,
    defaultMaxFiles: parsePositiveInt(process.env.SECURE_MCP_MAX_FILES, 400),
    maxFileBytes: parsePositiveInt(process.env.SECURE_MCP_MAX_FILE_BYTES, 256 * 1024),
    maxDepth: parsePositiveInt(process.env.SECURE_MCP_MAX_DEPTH, 12),
  };
}
