import assert from "node:assert/strict";
import { type ChildProcessWithoutNullStreams, spawn } from "node:child_process";
import { once } from "node:events";
import path from "node:path";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { MODERN_PROTOCOL_VERSION, PROJECT_VERSION } from "./test-constants.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serverEntry = path.join(root, "src", "index.ts");

type JsonRpcMessage = {
  jsonrpc: "2.0";
  id?: number;
  method?: string;
  params?: Record<string, unknown>;
  result?: Record<string, unknown>;
  error?: { code: number; message: string; data?: Record<string, unknown> };
};

async function closeChild(child: ChildProcessWithoutNullStreams): Promise<void> {
  if (child.exitCode !== null) return;

  const exited = once(child, "exit");
  child.stdin.end();
  const timer = setTimeout(() => child.kill("SIGTERM"), 2_000);
  timer.unref();
  await exited;
  clearTimeout(timer);
}

test("strict v2 server rejects a legacy initialize opening", { timeout: 20_000 }, async () => {
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

  async function nextResponse(): Promise<JsonRpcMessage> {
    const next = await output.next();
    assert.equal(next.done, false, `Server stdout closed early. stderr: ${stderr.join("")}`);
    let response: JsonRpcMessage;
    try {
      response = JSON.parse(next.value) as JsonRpcMessage;
    } catch {
      assert.fail(`Non-protocol stdout from server: ${next.value}`);
    }
    return response;
  }

  try {
    await once(child, "spawn");

    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 1,
        method: "initialize",
        params: {
          protocolVersion: "2025-06-18",
          capabilities: {},
          clientInfo: { name: "secure-mcp-legacy-probe", version: PROJECT_VERSION },
        },
      })}\n`,
    );

    const rejection = await nextResponse();
    assert.equal(rejection.id, 1);
    assert.ok(
      rejection.error,
      `Legacy initialize was not rejected with an error: ${JSON.stringify(rejection)}`,
    );
    assert.equal(
      rejection.error?.code,
      -32022,
      `Expected SDK v2 unsupported-protocol-version error (-32022), got ${JSON.stringify(rejection.error)}`,
    );
    assert.match(rejection.error?.message ?? "", /unsupported protocol version/i);
    assert.ok(
      (rejection.error?.data?.supported as string[] | undefined)?.includes(MODERN_PROTOCOL_VERSION),
      `Rejection must name ${MODERN_PROTOCOL_VERSION}: ${JSON.stringify(rejection.error)}`,
    );

    // The connection stays open for a modern opening after rejecting legacy.
    child.stdin.write(
      `${JSON.stringify({
        jsonrpc: "2.0",
        id: 2,
        method: "server/discover",
        params: {
          _meta: {
            "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
            "io.modelcontextprotocol/clientInfo": {
              name: "secure-mcp-wire-test",
              version: PROJECT_VERSION,
            },
            "io.modelcontextprotocol/clientCapabilities": {},
          },
        },
      })}\n`,
    );

    const discover = await nextResponse();
    assert.equal(discover.id, 2);
    assert.equal(discover.error, undefined, JSON.stringify(discover.error));
    assert.ok(
      (discover.result?.supportedVersions as string[] | undefined)?.includes(MODERN_PROTOCOL_VERSION),
    );
  } finally {
    lines.close();
    await closeChild(child);
  }
});
