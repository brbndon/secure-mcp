import assert from "node:assert/strict";
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { LEGACY_PROTOCOL_VERSION, MODERN_PROTOCOL_VERSION, PROJECT_VERSION, REQUIRED_TOOLS } from "./test-constants.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serverEntry = path.join(root, "src", "index.ts");
const fixture = path.join(root, "fixtures", "tiny-app");

type JsonRpcMessage = {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string };
};

function modernMeta(): Record<string, unknown> {
  return {
    "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
    "io.modelcontextprotocol/clientInfo": {
      name: "secure-mcp-wire-test",
      version: PROJECT_VERSION,
    },
    "io.modelcontextprotocol/clientCapabilities": {},
  };
}

async function closeChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null) return;

  const exited = once(child, "exit");
  child.stdin.end();
  const timer = setTimeout(() => child.kill("SIGTERM"), 2_000);
  timer.unref();
  await exited;
  clearTimeout(timer);
}

test("modern stdio serves discovery and tools without the legacy handshake", { timeout: 20_000 }, async () => {
  const child = spawn("pnpm", ["exec", "tsx", serverEntry], {
    cwd: root,
    env: {
      ...process.env,
      SECURE_MCP_ALLOWED_ROOTS: root,
    },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => stderr.push(chunk));

  const lines = createInterface({ input: child.stdout });
  const output = lines[Symbol.asyncIterator]();
  const exchange: JsonRpcMessage[] = [];

  async function request(message: JsonRpcMessage): Promise<JsonRpcMessage> {
    exchange.push(message);
    child.stdin.write(`${JSON.stringify(message)}\n`);

    const next = await output.next();
    assert.equal(next.done, false, `Server stdout closed early. stderr: ${stderr.join("")}`);

    let response: JsonRpcMessage;
    try {
      response = JSON.parse(next.value) as JsonRpcMessage;
    } catch {
      assert.fail(`Non-protocol stdout from server: ${next.value}`);
    }
    exchange.push(response);
    assert.equal(response.id, message.id, `Unexpected response id: ${JSON.stringify(response)}`);
    assert.equal(response.error, undefined, `JSON-RPC error: ${JSON.stringify(response.error)}`);
    return response;
  }

  try {
    await once(child, "spawn");

    const discover = await request({
      jsonrpc: "2.0",
      id: 1,
      method: "server/discover",
      params: { _meta: modernMeta() },
    });
    const supportedVersions = discover.result?.supportedVersions;
    assert.ok(Array.isArray(supportedVersions));
    assert.ok(supportedVersions.includes(MODERN_PROTOCOL_VERSION));
    assert.ok(
      !supportedVersions.some((version) => String(version).startsWith("2025-")),
      `Strict v2 server offered a 2025-era protocol: ${supportedVersions.join(", ")}`,
    );
    assert.ok(
      !supportedVersions.includes(LEGACY_PROTOCOL_VERSION),
      `Strict v2 server must not offer legacy protocol ${LEGACY_PROTOCOL_VERSION}`,
    );

    const listed = await request({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/list",
      params: { _meta: modernMeta() },
    });
    const tools = listed.result?.tools;
    assert.ok(Array.isArray(tools));
    assert.equal(tools.length, REQUIRED_TOOLS.length);
    for (const tool of tools) {
      assert.equal(typeof tool.name, "string");
      assert.equal(tool.inputSchema?.type, "object");
    }
    assert.deepEqual(
      new Set(tools.map((tool) => tool.name)),
      new Set(REQUIRED_TOOLS),
    );

    const called = await request({
      jsonrpc: "2.0",
      id: 3,
      method: "tools/call",
      params: {
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: fixture, response_format: "json" },
        _meta: modernMeta(),
      },
    });
    assert.notEqual(called.result?.isError, true);
    const content = called.result?.content;
    assert.ok(Array.isArray(content));
    assert.ok(content.length > 0);
    assert.equal(content[0]?.type, "text");
    assert.equal(typeof content[0]?.text, "string");
    assert.ok(content[0].text.length > 0);

    const methods = exchange.flatMap((message) => (message.method ? [message.method] : []));
    assert.ok(methods.includes("server/discover"));
    assert.ok(!methods.includes("initialize"), `Modern exchange used initialize: ${methods.join(", ")}`);
    assert.ok(
      !methods.includes("notifications/initialized"),
      `Modern exchange used notifications/initialized: ${methods.join(", ")}`,
    );
  } finally {
    lines.close();
    await closeChild(child);
  }
});
