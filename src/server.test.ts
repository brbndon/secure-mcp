import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/client";
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

  it("adds Next.js injection detectors only for nextjs focus or detected nextjs", () => {
    assert.equal(shouldRunNextjsInjectionDetectors("typescript"), false);
    assert.equal(shouldRunNextjsInjectionDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsInjectionDetectors("auto", ["common", "nextjs"]), true);
    assert.equal(shouldRunNextjsInjectionDetectors("auto", ["common", "swift"]), false);
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

  it("runs common injection detectors for an Expo-focused MCP scan", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-expo-injection-"));
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
        path.join(root, "App.tsx"),
        "export const run = (input: string) => eval(input);\n",
        "utf8",
      );
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_injection_risks",
        arguments: { project_root: root, stack: "expo", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        findings: Array<{ root_control?: string }>;
        applied_pack_ids: string[];
        coverage: {
          files_reviewed: string[];
          review_basis: string;
          scan_status: string;
          not_observed_means: string;
        };
        knowledge_pack_traceability: { detector_families_run: string[] };
      };
      assert.ok(data.findings.some((finding) => finding.root_control === "INJ-EVAL"));
      assert.ok(data.applied_pack_ids.includes("core"));
      assert.ok(data.knowledge_pack_traceability.detector_families_run.includes("core.injection"));
      assert.deepEqual(data.coverage.files_reviewed, ["App.tsx"]);
      assert.equal(data.coverage.review_basis, "content_review");
      assert.equal(data.coverage.scan_status, "complete");
      assert.equal(data.coverage.not_observed_means, "no_candidate_in_files_reviewed");
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not issue content-review receipts when no injection detector applies", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-injection-receipt-"));
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
      await fs.writeFile(path.join(root, "App.tsx"), "export const safe = true;\n", "utf8");
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_injection_risks",
        arguments: { project_root: root, stack: "swift", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const coverage = (result.structuredContent as {
        coverage: {
          excluded_paths: Array<{ path: string; reason: string }>;
          files_reviewed: string[];
          review_basis: string;
          scan_status: string;
          not_observed_means: string;
        };
      }).coverage;
      assert.deepEqual(coverage.files_reviewed, []);
      assert.equal(coverage.review_basis, "inventory_only");
      assert.equal(coverage.scan_status, "partial");
      assert.equal(coverage.not_observed_means, "inventory_only_contents_not_reviewed");
      assert.ok(
        coverage.excluded_paths.some(
          (entry) =>
            entry.path === "App.tsx" && entry.reason === "no_applicable_injection_detectors",
        ),
      );
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("applies caller file caps to profiling and redacts inventory paths", async () => {
    const githubToken = `ghp_${"B".repeat(32)}`;
    const root = await fs.mkdtemp(
      path.join(os.tmpdir(), `secure-mcp-inventory-${githubToken}-`),
    );
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
      assert.ok(!markdownInventory.text.replaceAll("\\", "").includes(githubToken));
      assert.ok(!JSON.stringify(markdownInventoryResult.structuredContent).includes(githubToken));

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

describe("architecture typed surfaces", () => {
  it("returns typed surfaces, coverage gaps, priority paths, and security brief", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-arch-surfaces-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 50,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });

    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({
          name: "fixture-next",
          dependencies: { next: "15.0.0", react: "19.0.0" },
        }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.mkdir(path.join(root, "app", "api", "items"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "items", "route.ts"),
        "export async function GET() { return Response.json({}); }\n",
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "app", "page.tsx"),
        "export default function Page() { return null; }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "src", "app", "account"), { recursive: true });
      await fs.writeFile(
        path.join(root, "src", "app", "account", "page.tsx"),
        "export default function AccountPage() { return null; }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "src", "pages"), { recursive: true });
      await fs.writeFile(
        path.join(root, "src", "pages", "dashboard.tsx"),
        "export default function Dashboard() { return null; }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "app", "api", "keys"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "keys", "service-account.json"),
        "{}",
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "middleware.ts"),
        "export function middleware() {}\n",
        "utf8",
      );
      await fs.writeFile(path.join(root, "app.json"), JSON.stringify({ expo: {} }), "utf8");
      await fs.mkdir(path.join(root, "components"), { recursive: true });
      await fs.writeFile(
        path.join(root, "components", "page.tsx"),
        "export default function Component() { return null; }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "lib"), { recursive: true });
      await fs.writeFile(
        path.join(root, "lib", "auth.ts"),
        "export function requireUser() {}\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "app", "api", "webhooks", "stripe"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "webhooks", "stripe", "route.ts"),
        "export async function POST() { return Response.json({}); }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "app", "api", "cron"), { recursive: true });
      await fs.writeFile(
        path.join(root, "app", "api", "cron", "route.ts"),
        "export async function GET() { return Response.json({}); }\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "src", "tools"), { recursive: true });
      await fs.writeFile(
        path.join(root, "src", "tools", "lookup.ts"),
        "export async function lookup() {}\n",
        "utf8",
      );
      await fs.mkdir(path.join(root, "src", "trpc"), { recursive: true });
      await fs.writeFile(path.join(root, "src", "trpc", "router.ts"), "export const router = {};\n", "utf8");
      await fs.mkdir(path.join(root, "src", "workers"), { recursive: true });
      await fs.writeFile(path.join(root, "src", "workers", "ingest.ts"), "export async function ingest() {}\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, stack: "nextjs", max_files: 50, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        stacks: string[];
        surface: Record<string, string[]>;
        surfaces: Array<{
          kind: string;
          exposure: string;
          paths: string[];
          auth_expectation: string;
        }>;
        coverage_gaps: Array<{ kind: string; paths: string[]; suggested_tools: string[] }>;
        priority_paths: string[];
        security_brief: {
          stacks: string[];
          coverage_gap_count: number;
          high_value_surfaces: unknown[];
          priority_paths: string[];
        };
        threat_highlights: Array<{ stack: string; pack_id: string; id: string; text: string }>;
        trust_boundaries: string[];
      };

      assert.ok(data.stacks.includes("nextjs"));
      assert.ok(Array.isArray(data.surface.api_routes));
      assert.ok(data.surfaces.length > 0);
      assert.ok(data.surfaces.some((s) => s.kind === "http_route"));
      assert.ok(data.surfaces.some((s) => s.kind === "middleware" || s.kind === "auth_surface"));
      assert.ok(data.surfaces.some((s) => s.kind === "webhook"));
      assert.ok(data.surfaces.some((s) => s.kind === "cron"));
      assert.ok(data.surfaces.some((s) => s.kind === "agent_tool"));
      assert.ok(data.surfaces.some((s) => s.kind === "rpc"));
      assert.ok(data.surfaces.some((s) => s.kind === "queue"));
      for (const surface of data.surfaces) {
        assert.ok(surface.auth_expectation.length > 0);
        assert.ok(["public", "internal", "unknown"].includes(surface.exposure));
        // stack-honest: nextjs forced should not invent pure mobile-only kinds without paths
        assert.ok(!["deep_link", "webview", "secure_storage"].includes(surface.kind));
      }
      const pageEntry = data.surfaces.find((s) => s.kind === "page_entry");
      assert.ok(pageEntry);
      assert.ok(!pageEntry.paths.includes("components/page.tsx"));
      assert.ok(pageEntry.paths.includes("src/app/account/page.tsx"));
      assert.ok(pageEntry.paths.includes("src/pages/dashboard.tsx"));
      const authSurface = data.surfaces.find((s) => s.kind === "auth_surface");
      assert.equal(authSurface?.exposure, "unknown");
      assert.ok(!JSON.stringify(data).includes("service-account.json"));
      assert.ok(JSON.stringify(data).includes("[redacted-secret-file]"));
      assert.ok(data.coverage_gaps.length > 0);
      assert.ok(
        data.coverage_gaps.every((gap) =>
          /architecture inventory only.*after auth\/injection\/secrets tools/i.test(
            (gap as { reason?: string }).reason ?? "",
          ),
        ),
      );
      assert.ok(data.priority_paths.length > 0);
      assert.ok(data.security_brief.coverage_gap_count === data.coverage_gaps.length);
      assert.ok(data.security_brief.high_value_surfaces.length > 0);
      assert.ok(data.trust_boundaries.length > 0);
      assert.ok(data.threat_highlights.some((item) => item.id === "NEXT-MIDDLEWARE-AUTH"));
      assert.ok(!data.threat_highlights.some((item) => item.pack_id === "swift-ios"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not invent Next-only surfaces for a Swift root", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-arch-swift-"));
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
      await fs.writeFile(path.join(root, "Package.swift"), "// swift-tools-version: 5.9\n", "utf8");
      await fs.writeFile(path.join(root, "App.swift"), "import SwiftUI\n@main struct App {}\n", "utf8");
      await fs.writeFile(
        path.join(root, "KeychainStore.swift"),
        "import Security\nenum KeychainStore {}\n",
        "utf8",
      );
      await fs.writeFile(path.join(root, "app.json"), JSON.stringify({ expo: { name: "x" } }), "utf8");
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, stack: "swift", max_files: 40, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        stacks: string[];
        surfaces: Array<{ kind: string }>;
        threat_highlights: Array<{ stack: string; pack_id: string; text: string }>;
      };
      assert.ok(data.stacks.includes("swift"));
      assert.ok(!data.surfaces.some((s) => s.kind === "server_action"));
      assert.ok(!data.surfaces.some((s) => s.kind === "middleware"));
      assert.ok(!data.surfaces.some((s) => s.kind === "page_entry"));
      assert.ok(!data.surfaces.some((s) => s.kind === "deep_link"));
      assert.ok(!data.surfaces.some((s) => s.kind === "webhook"));
      assert.ok(!data.surfaces.some((s) => s.kind === "cron"));
      assert.ok(!data.surfaces.some((s) => s.kind === "agent_tool"));
      assert.ok(!data.surfaces.some((s) => s.kind === "rpc"));
      assert.ok(!data.surfaces.some((s) => s.kind === "queue"));
      assert.ok(data.threat_highlights.some((item) => item.pack_id === "swift-ios"));
      assert.ok(!data.threat_highlights.some((item) => item.stack === "nextjs"));
      assert.ok(!data.threat_highlights.some((item) => /server action|middleware/i.test(item.text)));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("keeps every typed path honest for forced stacks in a mixed tree", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-arch-mixed-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 80,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { next: "15.0.0", expo: "53.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.writeFile(path.join(root, "app.json"), JSON.stringify({ expo: { name: "x" } }), "utf8");
      await fs.writeFile(path.join(root, "Package.swift"), "// swift-tools-version: 5.9\n", "utf8");
      await fs.mkdir(path.join(root, "src", "app", "login"), { recursive: true });
      await fs.writeFile(path.join(root, "src", "app", "login", "page.tsx"), "export default 1;\n", "utf8");
      await fs.writeFile(path.join(root, "App.tsx"), "export default function App() {}\n", "utf8");
      await fs.writeFile(path.join(root, "Linking.ts"), "export const redirect = 'app://callback';\n", "utf8");
      await fs.writeFile(path.join(root, "App.swift"), "import SwiftUI\n@main struct App {}\n", "utf8");
      await fs.writeFile(path.join(root, "KeychainStore.swift"), "import Security\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);

      const expectations = {
        nextjs: {
          included: ["src/app/login/page.tsx"],
          excluded: ["App.tsx", "Linking.ts", "App.swift", "KeychainStore.swift", "Package.swift", "app.json"],
        },
        typescript: {
          included: ["package.json"],
          excluded: ["App.swift", "KeychainStore.swift", "Package.swift", "app.json", "next.config.js"],
        },
        swift: {
          included: ["App.swift", "KeychainStore.swift", "Package.swift"],
          excluded: ["App.tsx", "Linking.ts", "package.json", "app.json", "next.config.js"],
        },
        expo: {
          included: ["App.tsx", "Linking.ts", "package.json", "app.json"],
          excluded: ["App.swift", "KeychainStore.swift", "Package.swift", "next.config.js"],
        },
      } as const;

      for (const [stack, expected] of Object.entries(expectations)) {
        const result = await client.callTool({
          name: "secure_mcp_analyze_architecture",
          arguments: { project_root: root, stack, max_files: 80, response_format: "json" },
        });
        assert.equal(result.isError, undefined);
        const data = result.structuredContent as {
          surface: Record<string, string[]>;
          surfaces: Array<{ kind: string; paths: string[]; stacks: string[] }>;
        };
        const typedPaths = [...new Set(data.surfaces.flatMap((surface) => surface.paths))];
        for (const included of expected.included) {
          assert.ok(typedPaths.includes(included), `${stack} should include ${included}`);
        }
        for (const excluded of expected.excluded) {
          assert.ok(!typedPaths.includes(excluded), `${stack} should exclude ${excluded}`);
        }
        assert.ok(
          data.surfaces.every((surface) => surface.stacks.length === 1 && surface.stacks[0] === stack),
        );
        // The legacy buckets remain additive and stack-neutral for compatibility.
        assert.ok(Object.values(data.surface).flat().includes("KeychainStore.swift"));
      }
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("caps typed surface path lists and priority paths", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-arch-caps-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 100,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "cap-fixture", dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      for (let i = 0; i < 15; i += 1) {
        await fs.mkdir(path.join(root, "app", "api", `items-${i}`), { recursive: true });
        await fs.writeFile(
          path.join(root, "app", "api", `items-${i}`, "route.ts"),
          "export async function GET() { return Response.json({}); }\n",
          "utf8",
        );
      }
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_analyze_architecture",
        arguments: { project_root: root, stack: "nextjs", max_files: 100, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        surfaces: Array<{ kind: string; paths: string[] }>;
        coverage_gaps: Array<{ paths: string[] }>;
        priority_paths: string[];
      };
      const httpRoutes = data.surfaces.find((s) => s.kind === "http_route");
      assert.ok(httpRoutes);
      assert.ok(httpRoutes.paths.length <= 12);
      assert.ok(data.coverage_gaps.every((gap) => gap.paths.length <= 6));
      assert.ok(data.surfaces.length <= 20);
      assert.ok(data.surfaces.every((surface) => surface.paths.length <= 12));
      assert.ok(data.coverage_gaps.length <= 16);
      assert.ok(data.priority_paths.length <= 24);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
