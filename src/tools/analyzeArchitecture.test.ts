/**
 * Tests for analyze_architecture unsupported-stack honesty and authz path
 * prioritization (Tier 2 units B1 and B3).
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
import { unsupportedSignalsForEntries } from "./analyzeArchitecture.js";

describe("unsupportedSignalsForEntries", () => {
  it("maps marker files to stack signals without inventing packs", () => {
    const signals = unsupportedSignalsForEntries([
      "package.json",
      "pyproject.toml",
      "requirements.txt",
      "go.mod",
      "src/",
    ]);
    const stacks = signals.map((s) => s.stack);
    assert.ok(stacks.includes("python"));
    assert.ok(stacks.includes("go"));
    assert.ok(!stacks.includes("rust"));
    const python = signals.find((s) => s.stack === "python");
    assert.ok(python);
    assert.deepEqual(python.evidence, ["pyproject.toml", "requirements.txt"]);
  });

  it("returns no signals for a known Next.js layout", () => {
    const signals = unsupportedSignalsForEntries([
      "package.json",
      "next.config.js",
      "app/",
      "tsconfig.json",
    ]);
    assert.deepEqual(signals, []);
  });

  it("returns no signals for empty entries", () => {
    assert.deepEqual(unsupportedSignalsForEntries([]), []);
  });
});

describe("analyze_architecture unsupported-stack honesty", () => {
  it("reports limited generic review for a plain Python repo", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-python-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 40,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "requirements.txt"),
        "fastapi==0.115.0\nuvicorn==0.32.0\n",
        "utf8",
      );
      await fs.writeFile(path.join(root, "main.py"), "from fastapi import FastAPI\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        stacks: string[];
        recommended_packs: string[];
        unsupported_signals: Array<{ stack: string; frameworks: string[] }>;
        security_brief: { notes: string[] };
        notes: string[];
      };

      // Honest degrade: no fake stack confidence.
      assert.ok(!data.stacks.includes("nextjs"));
      assert.ok(!data.stacks.includes("typescript"));
      assert.ok(data.recommended_packs.includes("core"));
      assert.ok(data.recommended_packs.includes("secrets"));
      assert.ok(data.recommended_packs.includes("threat-model"));
      assert.ok(!data.recommended_packs.includes("web-next"));
      assert.ok(!data.recommended_packs.includes("web-api"));

      const python = data.unsupported_signals.find((s) => s.stack === "python");
      assert.ok(python, "expected python unsupported signal");
      assert.ok(python.frameworks.includes("fastapi"));

      const allNotes = [...data.notes, ...data.security_brief.notes].join("\n");
      assert.match(allNotes, /limited generic review/i);
      assert.match(allNotes, /python/i);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not flag unsupported stacks for a pure Next repo", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-next-clean-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 40,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "next-clean", dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        unsupported_signals: Array<{ stack: string }>;
        recommended_packs: string[];
      };
      assert.deepEqual(data.unsupported_signals, []);
      assert.ok(!data.recommended_packs.includes("expo-rn"));
      assert.ok(data.recommended_packs.includes("web-next"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
