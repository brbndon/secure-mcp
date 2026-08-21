/**
 * MCP server factory for secure-mcp.
 */

import { McpServer } from "@modelcontextprotocol/server";
import { loadConfig, type ServerConfig } from "./config.js";
import { registerAllTools } from "./tools/index.js";

/** Discovery and tool definitions are process-static and contain no caller-specific data. */
export const MCP_CATALOG_CACHE_TTL_MS = 5 * 60 * 1_000;

/**
 * Protocol-level orientation for agents, delivered on every discovery response.
 * Single source of truth for server identity text; if prompts are added later
 * they must consume this constant rather than duplicating the copy.
 */
export const SERVER_INSTRUCTIONS = [
  "secure-mcp performs defensive, remediation-focused secure code review of repositories under SECURE_MCP_ALLOWED_ROOTS; every tool is read-only.",
  "Preferred flow: secure_mcp_list_project_structure → secure_mcp_analyze_architecture → secure_mcp_get_knowledge_pack (pack_batches[0], detail=summary) → secure_mcp_check_authentication / secure_mcp_analyze_injection_risks / secure_mcp_review_secrets → read cited source and confirm candidates → secure_mcp_produce_findings with dispositions.",
  "Treat detector output as candidates, not confirmed weaknesses. Never generate exploits or use discovered secrets.",
  "Call secure_mcp_get_audit_guidance (section=workflow) for the full multi-phase playbook.",
].join(" ");

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
      instructions: SERVER_INSTRUCTIONS,
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
