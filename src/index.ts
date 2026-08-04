#!/usr/bin/env node
/**
 * secure-mcp — local stdio MCP server entrypoint.
 *
 * Coding agents connect via stdio to run structured security audits of
 * TypeScript/Next.js and Swift/SwiftUI repositories.
 *
 * Logging goes to stderr only (stdout is reserved for MCP protocol traffic).
 */

import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { loadConfig } from "./config.js";
import { requireValidLicense } from "./lib/license.js";
import { createServer } from "./server.js";

async function main(): Promise<void> {
  const config = loadConfig();

  // License gate: fail fast with a clear message if missing/invalid.
  try {
    const license = await requireValidLicense();
    console.error(
      `[secure-mcp] License OK (${license.keySource}${license.isDevKey ? ", development key" : ""}).`,
    );
    if (license.isDevKey) {
      console.error(
        "[secure-mcp] WARNING: SECURE_MCP_DEV_MODE=1 with development license key is active. " +
          "This allows startup for local development / agent / CI testing ONLY. " +
          "Do NOT use in production, do not process production data or secrets, and do not deploy with DEV_MODE enabled. " +
          "Production deployments must use a production license key without DEV_MODE.",
      );
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error(`[secure-mcp] License check failed: ${message}`);
    process.exit(1);
  }

  const server = createServer(config);
  const transport = new StdioServerTransport();

  await server.connect(transport);
  console.error(
    `[secure-mcp] ${config.name} v${config.version} running on stdio (Node ${process.version}).`,
  );
}

main().catch((error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  console.error(`[secure-mcp] Fatal: ${message}`);
  process.exit(1);
});
