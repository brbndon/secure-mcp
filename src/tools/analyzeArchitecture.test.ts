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
import { isAuthzSensitivePath, unsupportedSignalsForEntries } from "./analyzeArchitecture.js";

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
});

describe("isAuthzSensitivePath", () => {
  it("flags dynamic route segments, admin, webhooks, and server actions", () => {
    assert.equal(isAuthzSensitivePath("app/api/users/[id]/route.ts"), true);
    assert.equal(isAuthzSensitivePath("app/admin/settings/page.tsx"), true);
    assert.equal(isAuthzSensitivePath("app/api/webhooks/stripe/route.ts"), true);
    assert.equal(isAuthzSensitivePath("app/actions/create.ts"), true);
    assert.equal(isAuthzSensitivePath("app/onopenurl/linking.ts"), true);
  });

  it("does not flag generic routes or shared components", () => {
    assert.equal(isAuthzSensitivePath("app/api/search/route.ts"), false);
    assert.equal(isAuthzSensitivePath("components/button.tsx"), false);
    assert.equal(isAuthzSensitivePath("app/page.tsx"), false);
  });
});

describe("analyze_architecture authz prioritization", () => {
  it("ranks authz-sensitive paths first and annotates the security brief", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-authz-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 60,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "authz-fixture", dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.mkdir(path.join(root, "app", "api", "users", "[id]"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "users", "[id]", "route.ts"),
        "export async function GET() { return Response.json({}); }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "app", "api", "search"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "search", "route.ts"),
        "export async function GET() { return Response.json({}); }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "app", "api", "webhooks", "stripe"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "webhooks", "stripe", "route.ts"),
        "export async function POST() { return Response.json({}); }\n",
        "utf8",
      );

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, stack: "nextjs", max_files: 60, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        priority_paths: string[];
        security_brief: { notes: string[] };
        surfaces: Array<{ kind: string; paths: string[]; authz_sensitive: boolean }>;
      };

      const dynamicIndex = data.priority_paths.findIndex((p) =>
        p.includes("users/[id]"),
      );
      const searchIndex = data.priority_paths.findIndex((p) => p.includes("search"));
      assert.ok(dynamicIndex >= 0, "dynamic route should appear in priority paths");
      assert.ok(
        dynamicIndex < searchIndex,
        `dynamic route (${dynamicIndex}) should rank before generic search (${searchIndex})`,
      );

      const httpRoute = data.surfaces.find((s) => s.kind === "http_route");
      assert.ok(httpRoute);
      assert.equal(httpRoute.authz_sensitive, true);
      assert.ok(httpRoute.paths.some((p) => p.includes("users/[id]")));

      assert.match(data.security_brief.notes.join("\n"), /authorization-sensitive/i);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not mark a plain Next route as authz-sensitive", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-authz-clean-"));
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
        JSON.stringify({ name: "clean-next", dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.mkdir(path.join(root, "app", "api", "search"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "search", "route.ts"),
        "export async function GET() { return Response.json({}); }\n",
        "utf8",
      );

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, stack: "nextjs", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        surfaces: Array<{ authz_sensitive: boolean }>;
        security_brief: { notes: string[] };
      };
      assert.ok(!data.surfaces.some((s) => s.authz_sensitive));
      assert.ok(!data.security_brief.notes.some((n) => /authorization-sensitive/i.test(n)));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("analyze_architecture unsupported-stack honesty: no false positives", () => {
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
