/**
 * Tests for secure_mcp_run_local_scanners: default-off behavior, env gate,
 * timeout/allowlist classification, and finding-shape mapping. Scanners are
 * never executed in tests — a mock execFile is injected and real binaries are
 * expected to be absent in CI.
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { createServer } from "../server.js";
import {
  parseGitleaksJson,
  parseSemgrepJson,
  registerRunLocalScanners,
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

  it("treats non-zero exit with stdout as a completed report", async () => {
    const execFile: ExecFileFn = async () => {
      const err = new Error("Command failed: semgrep") as NodeJS.ErrnoException & {
        code?: number;
        stdout?: string;
        stderr?: string;
      };
      err.code = 1;
      err.stdout = JSON.stringify({ results: [{ check_id: "rule.one" }] });
      err.stderr = "";
      throw err;
    };
    const result = await runBinary(execFile, "semgrep", ["scan"], "/tmp", 1000);
    assert.equal(result.status, "ok");
    if (result.status === "ok") {
      assert.match(result.stdout, /rule\.one/);
    }
  });

  it("classifies a hard failure with JSON stdout as an error, not a clean scan", async () => {
    const execFile: ExecFileFn = async () => {
      const err = new Error("Command failed: semgrep") as NodeJS.ErrnoException & {
        code?: number;
        stdout?: string;
        stderr?: string;
      };
      err.code = 2;
      err.stdout = JSON.stringify({ errors: [{ message: "invalid config" }], results: [] });
      err.stderr = "semgrep: config error: missing rules\n";
      throw err;
    };
    const result = await runBinary(execFile, "semgrep", ["scan"], "/tmp", 1000);
    assert.equal(result.status, "error");
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

  it("returns null for malformed semgrep output", () => {
    assert.equal(parseSemgrepJson("not json"), null);
    assert.equal(parseSemgrepJson('{"results": "nope"}'), null);
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

  it("returns null for malformed gitleaks output", () => {
    assert.equal(parseGitleaksJson("not json"), null);
    assert.equal(parseGitleaksJson('{"not": "an array"}'), null);
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

  it("rejects remote-rule requests so scanner runs remain offline-only", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanners-offline-"));
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
        arguments: {
          project_root: root,
          enable: true,
          allow_remote_rules: true,
          response_format: "json",
        },
      });
      assert.equal(result.isError, true);
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

  it("reports scanner error status instead of a false clean when output is malformed", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanner-malformed-"));
    await fs.writeFile(path.join(root, ".semgrep.yml"), "rules: []\n", "utf8");
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = new McpServer({ name: "secure-mcp-test", version: "test" });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    const previous = process.env.SECURE_MCP_LOCAL_SCANNERS;
    const malformedExec: ExecFileFn = async () => ({ stdout: "definitely not json", stderr: "" });

    try {
      process.env.SECURE_MCP_LOCAL_SCANNERS = "1";
      registerRunLocalScanners(
        server,
        { name: "secure-mcp-test", version: "test", defaultMaxFiles: 20, maxFileBytes: 8192, maxDepth: 12, allowedRoots: [root] },
        malformedExec,
      );
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_run_local_scanners",
        arguments: { project_root: root, enable: true, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        enabled: boolean;
        scanners: Array<{ id: string; status: string; findings: number; note?: string }>;
        findings: unknown[];
      };
      assert.equal(data.enabled, true);
      // Malformed output must surface as an error, never as "completed" with
      // zero findings (which would read as a clean scan).
      const semgrep = data.scanners.find((s) => s.id === "semgrep");
      const gitleaks = data.scanners.find((s) => s.id === "gitleaks");
      assert.equal(semgrep?.status, "error");
      assert.ok(semgrep?.note?.includes("not valid JSON"), semgrep?.note);
      assert.equal(gitleaks?.status, "error");
      assert.ok(gitleaks?.note?.includes("not valid JSON"), gitleaks?.note);
      assert.deepEqual(data.findings, []);
    } finally {
      if (previous === undefined) delete process.env.SECURE_MCP_LOCAL_SCANNERS;
      else process.env.SECURE_MCP_LOCAL_SCANNERS = previous;
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("maps well-formed scanner output to completed status", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-scanner-valid-"));
    await fs.writeFile(path.join(root, ".semgrep.yml"), "rules: []\n", "utf8");
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = new McpServer({ name: "secure-mcp-test", version: "test" });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    const previous = process.env.SECURE_MCP_LOCAL_SCANNERS;
    const validExec: ExecFileFn = async (file: string) => ({
      stdout:
        file === "semgrep"
          ? JSON.stringify({
              results: [
                {
                  check_id: "semgrep.rule.one",
                  path: "app/main.ts",
                  start: { line: 5 },
                  extra: { message: "candidate", severity: "WARNING" },
                },
              ],
            })
          : JSON.stringify([
              {
                RuleID: "generic-api-key",
                Description: "Generic API Key",
                File: "config.json",
                StartLine: 3,
              },
            ]),
      stderr: "",
    });

    try {
      process.env.SECURE_MCP_LOCAL_SCANNERS = "1";
      registerRunLocalScanners(
        server,
        { name: "secure-mcp-test", version: "test", defaultMaxFiles: 20, maxFileBytes: 8192, maxDepth: 12, allowedRoots: [root] },
        validExec,
      );
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_run_local_scanners",
        arguments: { project_root: root, enable: true, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        enabled: boolean;
        scanners: Array<{ id: string; status: string; findings: number }>;
        findings: unknown[];
      };
      assert.equal(data.enabled, true);
      assert.equal(data.scanners.find((s) => s.id === "semgrep")?.status, "completed");
      assert.equal(data.scanners.find((s) => s.id === "semgrep")?.findings, 1);
      assert.equal(data.scanners.find((s) => s.id === "gitleaks")?.status, "completed");
      assert.equal(data.scanners.find((s) => s.id === "gitleaks")?.findings, 1);
      assert.equal(data.findings.length, 2);
    } finally {
      if (previous === undefined) delete process.env.SECURE_MCP_LOCAL_SCANNERS;
      else process.env.SECURE_MCP_LOCAL_SCANNERS = previous;
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
