import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk-v1/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk-v1/client/stdio.js";
import { REQUIRED_TOOLS } from "./test-constants.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serverEntry = path.join(root, "dist", "index.js");

test("SDK v1.30.0 client can initialize, list tools, call a tool, and close", { timeout: 20_000 }, async () => {
  assert.ok(existsSync(serverEntry), `Built server entrypoint is missing: ${serverEntry}. Run pnpm build first.`);

  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [serverEntry],
    cwd: root,
    env: {
      ...process.env,
      SECURE_MCP_ALLOWED_ROOTS: root,
    } as Record<string, string>,
  });
  const client = new Client({ name: "secure-mcp-v1-compat", version: "1.0.0" });

  try {
    await client.connect(transport);

    const listed = await client.listTools();
    assert.equal(listed.tools.length, REQUIRED_TOOLS.length);
    assert.deepEqual(
      new Set(listed.tools.map((tool) => tool.name)),
      new Set(REQUIRED_TOOLS),
    );

    const result = await client.callTool({
      name: "secure_mcp_get_audit_guidance",
      arguments: { section: "overview", response_format: "json" },
    });
    assert.notEqual(result.isError, true);
    assert.ok(Array.isArray(result.content));
  } finally {
    await client.close();
  }
});
