import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "./server.js";
import { shouldRunNextjsInjectionDetectors } from "./tools/analyzeInjectionRisks.js";

describe("server configuration and stack scoping", () => {
  it("passes configured scan limits through the MCP tool boundary", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-config-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 1,
      maxFileBytes: 1024,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(path.join(root, "a.ts"), "export const a = 1;\n", "utf8");
      await fs.writeFile(path.join(root, "b.ts"), "export const b = 2;\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: root, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        file_count: number;
        coverage: { caps: { max_files: number } };
      };
      assert.equal(data.coverage.caps.max_files, 1);
      assert.equal(data.file_count, 1);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("enforces configured byte limits for package and app metadata reads", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-metadata-cap-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 8,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { expo: "1.0.0" } }),
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "app.json"),
        JSON.stringify({ expo: { name: "fixture" } }),
        "utf8",
      );

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        stacks: string[];
        detection: { hasExpo: boolean };
        notable_dependencies: string[];
        coverage: {
          caps: { max_file_bytes: number };
          excluded_paths: Array<{ path: string; reason: string }>;
        };
      };
      assert.equal(data.coverage.caps.max_file_bytes, 8);
      assert.ok(
        data.coverage.excluded_paths.some(
          (entry) => entry.path === "package.json" && entry.reason === "max_file_bytes",
        ),
      );
      assert.ok(
        data.coverage.excluded_paths.some(
          (entry) => entry.path === "app.json" && entry.reason === "max_file_bytes",
        ),
      );
      assert.equal(data.detection.hasExpo, false);
      assert.ok(!data.stacks.includes("expo"));
      assert.ok(!data.notable_dependencies.includes("expo"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("clamps caller-supplied inventory depth to the configured maximum", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-depth-cap-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 1024,
      maxDepth: 1,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.mkdir(path.join(root, "level-one", "level-two"), { recursive: true });
      await fs.writeFile(
        path.join(root, "level-one", "level-two", "deep.ts"),
        "export const deep = true;\n",
        "utf8",
      );

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: root, max_depth: 20, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        sample_files: string[];
        coverage: {
          caps: { max_depth: number };
          excluded_paths: Array<{ path: string; reason: string }>;
        };
      };
      assert.equal(data.coverage.caps.max_depth, 1);
      assert.ok(!data.sample_files.includes("level-one/level-two/deep.ts"));
      assert.ok(
        data.coverage.excluded_paths.some(
          (entry) => entry.path === "level-one/level-two" && entry.reason === "max_depth",
        ),
      );
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not let caller-lower inventory depth influence profile signals", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-depth-profile-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 1024,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.mkdir(path.join(root, "level-one", "level-two"), { recursive: true });
      await fs.writeFile(
        path.join(root, "level-one", "level-two", "deep.ts"),
        "export const deep = true;\n",
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "level-one", "level-two", "Deep.swift"),
        "import SwiftUI\nstruct DeepView: View { var body: some View { Text(\"deep\") } }\n",
        "utf8",
      );

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: root, max_depth: 1, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        file_count: number;
        sample_files: string[];
        profile: {
          hasTypeScriptFiles: boolean;
          hasSwiftFiles: boolean;
          likelyStacks: string[];
        };
      };
      assert.equal(data.file_count, 0);
      assert.deepEqual(data.sample_files, []);
      assert.equal(data.profile.hasTypeScriptFiles, false);
      assert.equal(data.profile.hasSwiftFiles, false);
      assert.ok(!data.profile.likelyStacks.includes("typescript"));
      assert.ok(!data.profile.likelyStacks.includes("swift"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not add Next.js injection detectors to explicit TypeScript scans", () => {
    assert.equal(shouldRunNextjsInjectionDetectors("typescript"), false);
    assert.equal(shouldRunNextjsInjectionDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsInjectionDetectors("auto"), true);
  });

  it("keeps Next.js findings out of a TypeScript-focused MCP scan", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-stack-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 10,
      maxFileBytes: 1024,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "page.tsx"),
        "export function Page({ html }: { html: string }) { return <div dangerouslySetInnerHTML={{ __html: html }} />; }\n",
        "utf8",
      );
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_injection_risks",
        arguments: { project_root: root, stack: "typescript", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const findings = (result.structuredContent as {
        findings: Array<{ root_control?: string }>;
      }).findings;
      assert.ok(findings.some((finding) => finding.root_control === "INJ-DANGEROUS-HTML"));
      assert.ok(!findings.some((finding) => finding.root_control === "NEXT-DANGEROUS-HTML"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("applies caller file caps to profiling and redacts inventory paths", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-inventory-boundary-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 1024,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.mkdir(path.join(root, "nested"));
      await fs.writeFile(path.join(root, "a.ts"), "export const a = 1;\n", "utf8");
      await fs.writeFile(
        path.join(root, "nested", "z.swift"),
        "import SwiftUI\nstruct Z {}\n",
        "utf8",
      );
      await fs.writeFile(path.join(root, ".env.production"), "TOKEN=redacted-fixture\n", "utf8");
      await fs.writeFile(path.join(root, "server.pem"), "private-key-fixture\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);

      const inventoryResult = await client.callTool({
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: root, max_files: 1, response_format: "json" },
      });
      assert.equal(inventoryResult.isError, undefined);
      const inventory = inventoryResult.structuredContent as {
        file_count: number;
        profile: { hasSwiftFiles: boolean; topLevelEntries: string[] };
        sample_files: string[];
        coverage: { included_paths: string[] };
      };
      assert.equal(inventory.file_count, 1);
      assert.equal(inventory.profile.hasSwiftFiles, false);
      assert.ok(inventory.profile.topLevelEntries.includes("[redacted-secret-file]"));
      assert.ok(!JSON.stringify(inventory).includes(".env.production"));
      assert.ok(!JSON.stringify(inventory).includes("server.pem"));
      assert.ok(inventory.coverage.included_paths.length <= 1);

      const markdownInventoryResult = await client.callTool({
        name: "secure_mcp_list_project_structure",
        arguments: { project_root: root, max_files: 20, response_format: "markdown" },
      });
      const markdownInventory = markdownInventoryResult.content.find(
        (block) => block.type === "text",
      ) as { type: "text"; text: string } | undefined;
      assert.ok(markdownInventory);
      assert.ok(!markdownInventory.text.includes(".env.production"));
      assert.ok(!markdownInventory.text.includes("server.pem"));

      const architectureResult = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, max_files: 20, response_format: "json" },
      });
      assert.equal(architectureResult.isError, undefined);
      const architecture = architectureResult.structuredContent as {
        top_level: string[];
        coverage: { included_paths: string[] };
        surface: Record<string, string[]>;
      };
      assert.ok(architecture.top_level.includes("[redacted-secret-file]"));
      assert.ok(!JSON.stringify(architecture).includes(".env.production"));
      assert.ok(!JSON.stringify(architecture).includes("server.pem"));
      assert.ok(
        Object.values(architecture.surface)
          .flat()
          .every((entry) => !entry.includes(".env.production") && !entry.includes("server.pem")),
      );
      assert.ok(architecture.coverage.included_paths.length > 1);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("returns all sections from the all-guidance request", async () => {
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer();
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    await server.connect(serverTransport);
    await client.connect(clientTransport);
    try {
      const result = await client.callTool({
        name: "secure_mcp_get_audit_guidance",
        arguments: { section: "all", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const guidance = (result.structuredContent as { guidance: string }).guidance;
      assert.match(guidance, /Phase 1: secure_mcp_list_project_structure/);
      assert.match(guidance, /secure_mcp_review_secrets/);
      assert.match(guidance, /Every finding passed in/);
    } finally {
      await client.close();
      await server.close();
    }
  });
});
