/**
 * Tests for secure_mcp_run_local_scanners (Tier 2 unit B4):
 * default-off behavior, env gate, timeout/allowlist classification, and
 * finding-shape mapping. Scanners are never executed in tests — a mock execFile
 * is injected and real binaries are expected to be absent in CI.
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
import {
  parseGitleaksJson,
  parseSemgrepJson,
  runBinary,
  scannerEnvEnabled,
  scannersEnabled,
  type ExecFileFn,
} from "./runLocalScanners.js";

describe("scanner gating", () => {
  it("requires both the tool arg and the server env gate", () => {
    assert.equal(scannerEnvEnabled(undefined), false);
    assert.equal(scannerEnvEnabled("0"), false);
    assert.equal(scannerEnvEnabled("false"), false);
    assert.equal(scannerEnvEnabled("1"), true);
    assert.equal(scannerEnvEnabled("TRUE"), true);

    assert.equal(scannersEnabled(false, { SECURE_MCP_LOCAL_SCANNERS: "1" }), false);
    assert.equal(scannersEnabled(true, {}), false);
    assert.equal(scannersEnabled(true, { SECURE_MCP_LOCAL_SCANNERS: "0" }), false);
    assert.equal(scannersEnabled(true, { SECURE_MCP_LOCAL_SCANNERS: "1" }), true);
  });
});

describe("runBinary", () => {
  it("classifies missing binaries", async () => {
    const execFile: ExecFileFn = async () => {
      const err = new Error("spawn semgrep ENOENT") as NodeJS.ErrnoException;
      err.code = "ENOENT";
      throw err;
    };
    const result = await runBinary(execFile, "semgrep", ["scan"], "/tmp", 1000);
    assert.equal(result.status, "missing");
    assert.equal("binary" in result && result.binary, "semgrep");
  });

  it("classifies timeouts", async () => {
    const execFile: ExecFileFn = async () => {
      const err = new Error("killed") as NodeJS.ErrnoException & { killed?: boolean };
      err.killed = true;
      throw err;
    };
    const result = await runBinary(execFile, "semgrep", ["scan"], "/tmp", 1);
    assert.equal(result.status, "timeout");
  });

  it("returns ok with stdout on success", async () => {
    const execFile: ExecFileFn = async () => ({ stdout: "{}", stderr: "" });
    const result = await runBinary(execFile, "gitleaks", ["detect"], "/tmp", 1000);
    assert.equal(result.status, "ok");
    if (result.status === "ok") assert.equal(result.stdout, "{}");
  });
});

describe("scanner output mapping", () => {
  it("maps semgrep results to bounded candidates", () => {
    const json = JSON.stringify({
      results: [
        {
          check_id: "python.lang.security.audit.dangerous-subprocess-use",
          path: "app/main.py",
          start: { line: 10 },
          extra: { message: "Detected subprocess use", severity: "ERROR" },
        },
      ],
    });
    const mapped = parseSemgrepJson(json);
    assert.equal(mapped.length, 1);
    assert.equal(mapped[0].rule_family, "semgrep.python.lang.security.audit.dangerous-subprocess-use");
    assert.equal(mapped[0].severity, "high");
    assert.equal(mapped[0].file, "app/main.py");
    assert.equal(mapped[0].line, 10);
  });

  it("returns empty for malformed semgrep output", () => {
    assert.deepEqual(parseSemgrepJson("not json"), []);
    assert.deepEqual(parseSemgrepJson('{"results": "nope"}'), []);
  });

  it("maps gitleaks results without leaking the secret value", () => {
    const json = JSON.stringify([
      {
        RuleID: "generic-api-key",
        Description: "Generic API Key",
        File: "config.json",
        StartLine: 3,
        Secret: "super-secret-value",
        Match: "token=super-secret-value",
      },
    ]);
    const mapped = parseGitleaksJson(json);
    assert.equal(mapped.length, 1);
    assert.equal(mapped[0].category, "secrets");
    assert.equal(mapped[0].rule_family, "gitleaks.generic-api-key");
    assert.ok(!JSON.stringify(mapped).includes("super-secret-value"));
  });
});

describe("secure_mcp_run_local_scanners", () => {
  it("is a structured skip by default (enable=false)", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanners-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_run_local_scanners",
        arguments: { project_root: root, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        enabled: boolean;
        scanners: unknown[];
        findings: unknown[];
      };
      assert.equal(data.enabled, false);
      assert.deepEqual(data.scanners, []);
      assert.deepEqual(data.findings, []);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("fails closed when project_root is outside the allowlist", async () => {
    const allowed = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanner-allowed-"));
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanner-outside-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 8192,
      maxDepth: 12,
      allowedRoots: [allowed],
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    const previous = process.env.SECURE_MCP_LOCAL_SCANNERS;

    try {
      process.env.SECURE_MCP_LOCAL_SCANNERS = "1";
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_run_local_scanners",
        arguments: { project_root: outside, enable: true, response_format: "json" },
      });
      // Even with enable=true + env gate on, an out-of-allowlist root is rejected.
      assert.equal(result.isError, true);
    } finally {
      if (previous === undefined) delete process.env.SECURE_MCP_LOCAL_SCANNERS;
      else process.env.SECURE_MCP_LOCAL_SCANNERS = previous;
      await client.close();
      await server.close();
      await fs.rm(allowed, { recursive: true, force: true });
      await fs.rm(outside, { recursive: true, force: true });
    }
  });
});
