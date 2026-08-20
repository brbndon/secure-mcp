/**
 * MCP server factory for secure-mcp.
 */

import { McpServer } from "@modelcontextprotocol/server";
import { loadConfig, type ServerConfig } from "./config.js";
import { registerAllTools } from "./tools/index.js";

/** Discovery and tool definitions are process-static and contain no caller-specific data. */
export const MCP_CATALOG_CACHE_TTL_MS = 5 * 60 * 1_000;

/**
 * Create and configure the MCP server (tools registered; transport not connected yet).
 */
export function createServer(config: ServerConfig = loadConfig()): McpServer {
  const server = new McpServer(
    {
      name: config.name,
      version: config.version,
    },
    {
      cacheHints: {
        "server/discover": {
          ttlMs: MCP_CATALOG_CACHE_TTL_MS,
          cacheScope: "public",
        },
        "tools/list": {
          ttlMs: MCP_CATALOG_CACHE_TTL_MS,
          cacheScope: "public",
        },
      },
    },
  );

  registerAllTools(server, config);

  return server;
}
