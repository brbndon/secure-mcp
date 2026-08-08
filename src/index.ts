#!/usr/bin/env node
/**
 * secure-mcp — local stdio MCP server entrypoint.
 *
 * Coding agents connect via stdio to run structured security audits of
 * TypeScript/Next.js and Swift/SwiftUI repositories.
 *
 * Logging goes to stderr only (stdout is reserved for MCP protocol traffic).
 */

import { serveStdio } from "@modelcontextprotocol/server/stdio";
import { loadConfig } from "./config.js";
import { redactedEvidence } from "./lib/redact.js";
import { createServer } from "./server.js";

function safeDiagnostic(error: unknown): string {
  const raw = error instanceof Error ? error.message : String(error);
  return redactedEvidence(raw).replace(/\s+/g, " ").slice(0, 1_000);
}

async function main(): Promise<void> {
  const config = loadConfig();
  if (config.allowedRoots?.length === 0) {
    console.error(
      "[secure-mcp] WARNING: SECURE_MCP_ALLOWED_ROOTS is not configured; filesystem tools will reject project roots.",
    );
  }

  // Keep construction failures startup-fatal before the stdio message pump begins.
  let validationServer: ReturnType<typeof createServer> | undefined;
  try {
    validationServer = createServer(config);
  } finally {
    await validationServer?.close();
  }

  serveStdio(() => createServer(config), {
    legacy: "serve",
    onerror: (error) => {
      console.error(`[secure-mcp] Protocol error: ${safeDiagnostic(error)}`);
    },
  });
  console.error(
    `[secure-mcp] ${config.name} v${config.version} running on stdio (Node ${process.version}).`,
  );
}

main().catch((error: unknown) => {
  console.error(`[secure-mcp] Fatal: ${safeDiagnostic(error)}`);
  process.exit(1);
});
