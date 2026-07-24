/**
 * Smoke test: spawn secure-mcp over stdio, list tools, call core tools on fixtures.
 *
 * Usage:
 *   SECURE_MCP_LICENSE_KEY=smcp_dev_local_testing_key_v1 pnpm smoke
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { DEV_LICENSE_KEY } from "../src/lib/license.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const fixture = path.join(root, "fixtures", "tiny-app");
const expoFixture = path.join(root, "fixtures", "tiny-expo");
const serverEntry = path.join(root, "src", "index.ts");

const REQUIRED_TOOLS = [
  "secure_mcp_list_project_structure",
  "secure_mcp_analyze_architecture",
  "secure_mcp_get_knowledge_pack",
  "secure_mcp_check_authentication",
  "secure_mcp_analyze_injection_risks",
  "secure_mcp_review_secrets",
  "secure_mcp_build_remediation_threat_model",
  "secure_mcp_produce_findings",
] as const;

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function parseJsonPayload(result: { content?: unknown; structuredContent?: unknown }): Record<string, unknown> {
  if (result.structuredContent && typeof result.structuredContent === "object") {
    return result.structuredContent as Record<string, unknown>;
  }
  const text = textOf(result);
  try {
    return JSON.parse(text) as Record<string, unknown>;
  } catch {
    return { raw: text };
  }
}

async function main(): Promise<void> {
  const license = process.env.SECURE_MCP_LICENSE_KEY ?? DEV_LICENSE_KEY;
  process.env.SECURE_MCP_LICENSE_KEY = license;

  console.log("[smoke] Starting secure-mcp via tsx…");
  console.log(`[smoke] Fixture: ${fixture}`);

  const transport = new StdioClientTransport({
    command: "pnpm",
    args: ["exec", "tsx", serverEntry],
    cwd: root,
    env: {
      ...process.env,
      SECURE_MCP_LICENSE_KEY: license,
    } as Record<string, string>,
  });

  const client = new Client({ name: "secure-mcp-smoke", version: "1.0.0" });
  await client.connect(transport);

  try {
    const listed = await client.listTools();
    const names = new Set(listed.tools.map((t) => t.name));
    console.log(`[smoke] Tools listed: ${listed.tools.length}`);

    for (const name of REQUIRED_TOOLS) {
      assert(names.has(name), `Missing tool: ${name}`);
    }
    console.log("[smoke] All required tools present.");

    const structure = await client.callTool({
      name: "secure_mcp_list_project_structure",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert(!structure.isError, `list_project_structure failed: ${JSON.stringify(structure)}`);
    const structureText = textOf(structure);
    assert(structureText.includes("tiny-app") || structureText.includes("next"), structureText);
    console.log("[smoke] list_project_structure OK");

    const architecture = await client.callTool({
      name: "secure_mcp_analyze_architecture",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert(!architecture.isError, `analyze_architecture failed: ${JSON.stringify(architecture)}`);
    const arch = parseJsonPayload(architecture);
    assert(Array.isArray(arch.recommended_packs), "Expected recommended_packs array");
    const packs = arch.recommended_packs as string[];
    assert(packs.includes("core"), `expected core in recommended_packs: ${packs.join(",")}`);
    assert(packs.includes("web-next"), `expected web-next for tiny-app: ${packs.join(",")}`);
    assert(
      !packs.includes("expo-rn"),
      `tiny-app should not recommend expo-rn: ${packs.join(",")}`,
    );
    assert(Array.isArray(arch.pack_batches), "Expected pack_batches array");
    const batches = arch.pack_batches as string[][];
    assert(batches.length >= 1, "Expected at least one pack batch");
    assert(
      batches.every((b) => Array.isArray(b) && b.length <= 6),
      `pack_batches exceed max 6: ${JSON.stringify(batches)}`,
    );
    assert(
      packs.length <= 6,
      `tiny-app Next packs should fit one tool call (≤6), got ${packs.length}: ${packs.join(",")}`,
    );
    const checklist = arch.checklist_seed;
    assert(Array.isArray(checklist), "Expected small checklist_seed");
    assert(
      !("recommended_checklist" in arch),
      "recommended_checklist alias should be removed; use checklist_seed",
    );
    assert(
      (checklist as unknown[]).length <= 12,
      `Architecture checklist seed too large: ${(checklist as unknown[]).length}`,
    );
    console.log("[smoke] analyze_architecture OK (recommended_packs + pack_batches + lean seed)");

    const packSummary = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: batches[0],
        detail: "summary",
        max_items: 10,
        response_format: "json",
      },
    });
    assert(!packSummary.isError, `get_knowledge_pack summary failed: ${JSON.stringify(packSummary)}`);
    const packSum = parseJsonPayload(packSummary);
    assert(packSum.detail === "summary", "Expected detail=summary");
    assert(Array.isArray(packSum.items) && (packSum.items as unknown[]).length <= 10, "max_items not applied");
    assert(
      Array.isArray(packSum.applied_pack_ids) &&
        (packSum.applied_pack_ids as string[]).includes("core"),
      "Expected applied_pack_ids",
    );
    assert(
      !("available_packs" in packSum),
      "available_packs should be omitted by default (include_index=false)",
    );
    console.log("[smoke] get_knowledge_pack summary OK (no index by default)");

    const packFull = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: ["secrets"],
        detail: "full",
        max_items: 5,
        response_format: "json",
      },
    });
    assert(!packFull.isError, `get_knowledge_pack full failed: ${JSON.stringify(packFull)}`);
    const packFullData = parseJsonPayload(packFull);
    const fullItems = packFullData.items as Array<Record<string, unknown>>;
    assert(fullItems.length > 0 && fullItems.length <= 5, "full pack max_items failed");
    assert(
      typeof fullItems[0]?.description === "string" || typeof fullItems[0]?.remediation === "string",
      "full items should include richer fields",
    );
    console.log("[smoke] get_knowledge_pack full OK");

    const packWithIndex = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: ["core"],
        detail: "summary",
        max_items: 3,
        include_index: true,
        response_format: "json",
      },
    });
    assert(!packWithIndex.isError, `get_knowledge_pack include_index failed: ${JSON.stringify(packWithIndex)}`);
    const packIdx = parseJsonPayload(packWithIndex);
    assert(Array.isArray(packIdx.available_packs), "Expected available_packs when include_index=true");
    console.log("[smoke] get_knowledge_pack include_index OK");

    const badPack = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: { pack_ids: ["not-a-real-pack"] },
    });
    assert(
      badPack.isError === true || textOf(badPack).toLowerCase().includes("unknown"),
      "Expected error for invalid pack id",
    );
    console.log("[smoke] get_knowledge_pack invalid id OK");

    const expoArch = await client.callTool({
      name: "secure_mcp_analyze_architecture",
      arguments: { project_root: expoFixture, response_format: "json" },
    });
    assert(!expoArch.isError, `expo architecture failed: ${JSON.stringify(expoArch)}`);
    const expoData = parseJsonPayload(expoArch);
    const expoPacks = expoData.recommended_packs as string[];
    assert(expoPacks.includes("expo-rn"), `expected expo-rn: ${expoPacks.join(",")}`);
    assert(expoPacks.includes("core"), `expected core: ${expoPacks.join(",")}`);
    assert(!expoPacks.includes("swift-ios"), `expo fixture should not force swift: ${expoPacks.join(",")}`);
    assert(!expoPacks.includes("web-next"), `expo fixture should not force web-next: ${expoPacks.join(",")}`);
    console.log("[smoke] expo recommended_packs routing OK");

    const secrets = await client.callTool({
      name: "secure_mcp_review_secrets",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert(!secrets.isError, `review_secrets failed: ${JSON.stringify(secrets)}`);
    const secretsText = textOf(secrets);
    assert(
      secretsText.includes("findings") || secretsText.includes("SEC-"),
      "Expected secrets findings in response",
    );
    console.log("[smoke] review_secrets OK");

    const injections = await client.callTool({
      name: "secure_mcp_analyze_injection_risks",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert(!injections.isError, `analyze_injection_risks failed: ${JSON.stringify(injections)}`);
    const injText = textOf(injections);
    assert(injText.includes("findings"), "Expected injection-risk findings array");
    console.log("[smoke] analyze_injection_risks OK");

    const threat = await client.callTool({
      name: "secure_mcp_build_remediation_threat_model",
      arguments: {
        project_root: fixture,
        focus_area: "search API hardening",
        assets: ["session", "PII"],
        response_format: "json",
      },
    });
    assert(!threat.isError, `build_remediation_threat_model failed: ${JSON.stringify(threat)}`);
    console.log("[smoke] build_remediation_threat_model OK");

    const produced = await client.callTool({
      name: "secure_mcp_produce_findings",
      arguments: {
        project_root: fixture,
        report_title: "Smoke test remediation report",
        findings: [
          {
            id: "SMOKE-001",
            title: "Unsafe command construction in search route",
            description:
              "Search route passes a query parameter into a shell execution helper without parameterization.",
            severity: "critical",
            confidence: "high",
            category: "injection-risk",
            file: "app/api/search/route.ts",
            evidence: "exec(`echo ${q}`)",
            impact_if_unremediated:
              "Untrusted query input may influence process execution on the server host.",
            remediation:
              "Remove shell string interpolation; use safe APIs with fixed commands and argument arrays; validate input.",
            residual_risk:
              "Similar sinks may exist elsewhere until a full injection-risk review is complete.",
            verification_suggestion:
              "Add a unit/integration test that rejects unsafe query values; re-run secure_mcp_analyze_injection_risks.",
            cwe: "CWE-78",
          },
        ],
        response_format: "json",
      },
    });
    assert(!produced.isError, `produce_findings failed: ${JSON.stringify(produced)}`);
    const prodText = textOf(produced);
    assert(prodText.includes("F-001") || prodText.includes("executive_summary"), prodText);
    console.log("[smoke] produce_findings OK");

    const bad = await client.callTool({
      name: "secure_mcp_list_project_structure",
      arguments: { project_root: path.join(fixture, "does-not-exist-xyz") },
    });
    assert(
      bad.isError === true || textOf(bad).toLowerCase().includes("error"),
      "Expected error for missing root",
    );
    console.log("[smoke] invalid project_root error handling OK");

    console.log("\n[smoke] SUCCESS — all checks passed.");
  } finally {
    await client.close();
  }
}

function textOf(result: { content?: unknown }): string {
  const content = result.content;
  if (!Array.isArray(content)) return JSON.stringify(result);
  return content
    .map((part) => {
      if (part && typeof part === "object" && "text" in part) {
        return String((part as { text: string }).text);
      }
      return JSON.stringify(part);
    })
    .join("\n");
}

main().catch((err: unknown) => {
  console.error("[smoke] FAILED:", err instanceof Error ? err.message : err);
  process.exit(1);
});
