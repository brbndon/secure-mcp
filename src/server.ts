/**
 * MCP server factory for secure-mcp.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { loadConfig, type ServerConfig } from "./config.js";
import { registerAllTools } from "./tools/index.js";

/**
 * Create and configure the MCP server (tools registered; transport not connected yet).
 */
export function createServer(config: ServerConfig = loadConfig()): McpServer {
  const server = new McpServer({
    name: config.name,
    version: config.version,
  });

  registerAllTools(server);

  return server;
}
