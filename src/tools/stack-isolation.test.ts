/**
 * Stack-isolation tests for the tool and architecture surface.
 * Named tests (`iso-*`, `redact-envelope`, `skill-pointer`) guard
 * stack routing, redaction, and the thin security-auditor pointer.
 *
 * Run: pnpm exec tsx --test src/tools/stack-isolation.test.ts
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

async function withServer(
  run: (client: Client) => Promise<void>,
  config: { defaultMaxFiles?: number; maxFileBytes?: number; maxDepth?: number } = {},
): Promise<void> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer({
    name: "secure-mcp-isolation-test",
    version: "test",
    defaultMaxFiles: config.defaultMaxFiles ?? 80,
    maxFileBytes: config.maxFileBytes ?? 8192,
    maxDepth: config.maxDepth ?? 12,
  });
  const client = new Client({ name: "secure-mcp-isolation-client", version: "test" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    await run(client);
  } finally {
    await client.close();
    await server.close();
  }
}

async function tempDir(prefix: string): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), prefix));
}

async function callJson(
  client: Client,
  name: string,
  args: Record<string, unknown>,
): Promise<{ data: Record<string, unknown>; text: string }> {
  const result = await client.callTool({ name, arguments: args });
  assert.equal(result.isError, undefined, `tool ${name} errored: ${JSON.stringify(result)}`);
  const structured = (result.structuredContent ?? {}) as Record<string, unknown>;
  const text = Array.isArray(result.content)
    ? result.content
        .map((part) => (part && typeof part === "object" && "text" in part ? String((part as { text: string }).text) : ""))
        .join("\n")
    : "";
  return { data: structured, text };
}

describe("iso-expo surfaces — Expo/RN gets mobile kinds, never Next-only kinds", () => {
  it("emits RN surface kinds and no server_action/middleware/page_entry/http_route", async () => {
    const root = await tempDir("secure-mcp-iso-expo-");
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { expo: "~52.0.0", "react-native": "0.76.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "app.json"), JSON.stringify({ expo: { name: "x" } }), "utf8");
      await fs.writeFile(path.join(root, "App.tsx"), "export default function App() {}\n", "utf8");
      await fs.writeFile(path.join(root, "Linking.ts"), "export const scheme = 'app://callback';\n", "utf8");
      await fs.writeFile(path.join(root, "WebView.tsx"), "export default function WebView() {}\n", "utf8");
      await fs.writeFile(path.join(root, "SecureStore.ts"), "export const store = (k: string, v: string) => {};\n", "utf8");

      await withServer(async (client) => {
        const { data } = await callJson(client, "secure_mcp_analyze_architecture", {
          project_root: root,
          stack: "expo",
          response_format: "json",
        });
        const surfaces = data.surfaces as Array<{ kind: string }>;
        const kinds = new Set(surfaces.map((s) => s.kind));
        for (const expected of ["deep_link", "webview", "secure_storage", "app_entry"]) {
          assert.ok(kinds.has(expected), `expected RN surface kind ${expected}: ${[...kinds].join(",")}`);
        }
        for (const banned of ["server_action", "middleware", "page_entry", "http_route"]) {
          assert.ok(!kinds.has(banned), `Expo must not emit ${banned}: ${[...kinds].join(",")}`);
        }
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("iso-swift surfaces — pure Swift never emits Next page/middleware/server_action", () => {
  it("emits Swift kinds only, no Next-only kinds", async () => {
    const root = await tempDir("secure-mcp-iso-swift-");
    try {
      await fs.writeFile(path.join(root, "Package.swift"), "// swift-tools-version: 5.9\n", "utf8");
      await fs.writeFile(path.join(root, "App.swift"), "import SwiftUI\n@main struct App {}\n", "utf8");
      await fs.writeFile(path.join(root, "KeychainStore.swift"), "import Security\n", "utf8");
      await fs.writeFile(path.join(root, "WebView.swift"), "import WebKit\n", "utf8");

      await withServer(async (client) => {
        const { data } = await callJson(client, "secure_mcp_analyze_architecture", {
          project_root: root,
          stack: "swift",
          response_format: "json",
        });
        const surfaces = data.surfaces as Array<{ kind: string }>;
        const kinds = new Set(surfaces.map((s) => s.kind));
        for (const banned of ["server_action", "middleware", "page_entry", "http_route"]) {
          assert.ok(!kinds.has(banned), `Swift must not emit ${banned}: ${[...kinds].join(",")}`);
        }
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("mixed monorepo — union packs, batches, and an honest security_brief", () => {
  it("orders the union by priority and reports a complete security_brief", async () => {
    const root = await tempDir("secure-mcp-iso-mixed-");
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { next: "15.0.0", expo: "53.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.writeFile(path.join(root, "app.json"), JSON.stringify({ expo: { name: "x" } }), "utf8");
      await fs.mkdir(path.join(root, "src", "app", "api", "search"), { recursive: true });
      await fs.writeFile(path.join(root, "src", "app", "api", "search", "route.ts"), "export async function GET() {}\n", "utf8");
      await fs.writeFile(path.join(root, "App.tsx"), "export default function App() {}\n", "utf8");
      await fs.writeFile(path.join(root, "SecureStore.ts"), "export const store = () => {};\n", "utf8");

      await withServer(async (client) => {
        const { data } = await callJson(client, "secure_mcp_analyze_architecture", {
          project_root: root,
          response_format: "json",
        });
        const packs = data.recommended_packs as string[];
        assert.equal(packs[0], "core", packs.join(","));
        assert.equal(packs[1], "secrets", packs.join(","));
        assert.ok(packs.includes("web-next"), packs.join(","));
        assert.ok(packs.includes("expo-rn"), packs.join(","));
        const batches = data.pack_batches as string[][];
        assert.ok(Array.isArray(batches) && batches.length >= 1);
        for (const batch of batches) assert.ok(batch.length <= 6, JSON.stringify(batches));

        const brief = data.security_brief as Record<string, unknown>;
        assert.ok(brief, "security_brief must be present");
        for (const key of ["stacks", "trust_boundaries", "high_value_surfaces", "coverage_gap_count", "recommended_packs", "priority_paths", "notes"]) {
          assert.ok(key in brief, `security_brief missing ${key}`);
        }
        assert.equal(brief.coverage_gap_count, (data.coverage_gaps as unknown[]).length);
        assert.equal(typeof data.surfaces_truncated, "boolean", "surfaces_truncated must be reported");
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("redact-envelope — known secrets never appear raw in tool output", () => {
  // Constructed fixtures (not real credentials) so push-protection scanners do not flag them.
  const AWS_KEY = `AKIA${"A".repeat(16)}`;
  const STRIPE_KEY = `sk_live_${"A".repeat(24)}`;
  const GITHUB_TOKEN = `ghp_${"B".repeat(36)}`;

  it("redacts secret paths and token values across tool envelopes", async () => {
    const root = await tempDir("secure-mcp-iso-redact-");
    try {
      await fs.writeFile(path.join(root, "package.json"), JSON.stringify({ dependencies: { next: "15.0.0" } }), "utf8");
      await fs.writeFile(path.join(root, ".env"), `AWS_ACCESS_KEY_ID=${AWS_KEY}\nSTRIPE_KEY=${STRIPE_KEY}\n`, "utf8");
      await fs.writeFile(
        path.join(root, "service-account.json"),
        JSON.stringify({ type: "service_account", token: GITHUB_TOKEN }),
        "utf8",
      );
      await fs.mkdir(path.join(root, "app"), { recursive: true });
      await fs.writeFile(path.join(root, "app", "page.tsx"), "export default function Page() {}\n", "utf8");

      await withServer(async (client) => {
        const structure = await callJson(client, "secure_mcp_list_project_structure", {
          project_root: root,
          response_format: "json",
        });
        const structureSerialized = `${JSON.stringify(structure.data)}\n${structure.text}`;
        assert.ok(!structureSerialized.includes("service-account.json"), "secret filename leaked in structure");
        assert.ok(!structureSerialized.includes(AWS_KEY), "AWS key leaked in structure");
        assert.ok(!structureSerialized.includes(STRIPE_KEY), "Stripe key leaked in structure");
        assert.ok(!structureSerialized.includes(GITHUB_TOKEN), "GitHub token leaked in structure");
        assert.ok(structureSerialized.includes("[redacted-secret-file]"), "expected a redaction marker");

        const secrets = await callJson(client, "secure_mcp_review_secrets", {
          project_root: root,
          response_format: "json",
        });
        const secretsSerialized = `${JSON.stringify(secrets.data)}\n${secrets.text}`;
        for (const secret of [AWS_KEY, STRIPE_KEY, GITHUB_TOKEN]) {
          assert.ok(!secretsSerialized.includes(secret), `secret leaked in review_secrets: ${secret}`);
        }
      });
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("skill-pointer — companion docs are pointers, not second playbooks", () => {
  it("keeps security-auditor.md a ≤40-line pointer without a full phase list", async () => {
    const content = await fs.readFile(path.join(REPO_ROOT, "skills", "security-auditor.md"), "utf8");
    const lines = content.split("\n").filter((line) => line.trim().length > 0);
    assert.ok(lines.length <= 40, `security-auditor.md has ${lines.length} non-empty lines; keep it a pointer`);
    assert.ok(content.includes(".agents/skills/secure-mcp/SKILL.md"), "must link the master skill path");
    assert.ok(!/\bPhase 1\b/i.test(content), "must not re-list Phase 1 as a full playbook");
    assert.ok(!/\bPhase 2\b/i.test(content), "must not re-list Phase 2 as a full playbook");
  });
});
