/**
 * Smoke test: spawn secure-mcp over stdio, list tools, call core tools on fixtures.
 *
 * Usage:
 *   pnpm smoke
 */

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { MODERN_PROTOCOL_VERSION, PROJECT_VERSION, REQUIRED_TOOLS } from "./test-constants.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const fixture = path.join(root, "fixtures", "tiny-app");
const expoFixture = path.join(root, "fixtures", "tiny-expo");
/** React-native library with a non-Expo app.json — must not route to expo-rn. */
const rnLibFixture = path.join(root, "fixtures", "rn-lib-no-expo");
const serverEntry = path.join(root, "src", "index.ts");

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
  console.log("[smoke] Starting secure-mcp via tsx…");
  console.log(`[smoke] Fixture: ${fixture}`);

  const transport = new StdioClientTransport({
    command: "pnpm",
    args: ["exec", "tsx", serverEntry],
    cwd: root,
    env: {
      ...process.env,
      SECURE_MCP_ALLOWED_ROOTS: root,
    } as Record<string, string>,
  });

  const client = new Client(
    { name: "secure-mcp-smoke", version: PROJECT_VERSION },
    {
      versionNegotiation: {
        mode: { pin: MODERN_PROTOCOL_VERSION },
      },
    },
  );
  await client.connect(transport);

  try {
    assert(client.getProtocolEra() === "modern", "Expected a modern protocol connection");
    assert(
      client.getNegotiatedProtocolVersion() === MODERN_PROTOCOL_VERSION,
      `Expected protocol ${MODERN_PROTOCOL_VERSION}, got ${client.getNegotiatedProtocolVersion()}`,
    );
    assert(
      client.getDiscoverResult()?.supportedVersions.includes(MODERN_PROTOCOL_VERSION),
      `server/discover did not offer ${MODERN_PROTOCOL_VERSION}`,
    );
    console.log(`[smoke] Modern protocol ${MODERN_PROTOCOL_VERSION} negotiated via server/discover.`);

    const listed = await client.listTools();
    const names = new Set(listed.tools.map((t) => t.name));
    console.log(`[smoke] Tools listed: ${listed.tools.length}`);

    assert(listed.tools.length === REQUIRED_TOOLS.length, `Expected exactly ${REQUIRED_TOOLS.length} tools`);
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
        response_format: "json",
      },
    });
    assert(!packSummary.isError, `get_knowledge_pack summary failed: ${JSON.stringify(packSummary)}`);
    const packSum = parseJsonPayload(packSummary);
    assert(packSum.detail === "summary", "Expected detail=summary");
    assert(
      Array.isArray(packSum.items) && (packSum.items as unknown[]).length > 0,
      "Expected summary items",
    );
    assert(
      Array.isArray(packSum.applied_pack_ids) &&
        (packSum.applied_pack_ids as string[]).includes("core"),
      "Expected applied_pack_ids",
    );
    assert(
      !("available_packs" in packSum),
      "available_packs should be omitted by default (include_index=false)",
    );
    const itemsPerPack = packSum.items_per_pack as Record<string, number> | undefined;
    assert(
      itemsPerPack && typeof itemsPerPack === "object",
      "Expected items_per_pack coverage map",
    );
    for (const id of packSum.applied_pack_ids as string[]) {
      assert(
        (itemsPerPack[id] ?? 0) >= 1,
        `expected ≥1 item from applied pack ${id}, got ${itemsPerPack[id] ?? 0}`,
      );
    }
    assert(
      (itemsPerPack["web-next"] ?? 0) >= 1,
      `tiny-app multi-pack summary should include web-next items: ${JSON.stringify(itemsPerPack)}`,
    );
    console.log("[smoke] get_knowledge_pack summary OK (fair multi-pack + no index by default)");

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
    const guidance = await client.callTool({
      name: "secure_mcp_get_audit_guidance",
      arguments: { section: "overview", response_format: "json" },
    });
    assert(!guidance.isError, "get_audit_guidance failed");
    console.log("[smoke] get_audit_guidance OK");

    const focusedArch = await client.callTool({
      name: "secure_mcp_analyze_architecture",
      arguments: { project_root: fixture, focus_paths: ["app"], response_format: "json" },
    });
    assert(!focusedArch.isError, "focused arch failed");
    console.log("[smoke] analyze_architecture with focus_paths OK");


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

    const expoPackLoad = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: expoPacks.slice(0, 6),
        detail: "summary",
        response_format: "json",
      },
    });
    assert(!expoPackLoad.isError, `expo get_knowledge_pack failed: ${JSON.stringify(expoPackLoad)}`);
    const expoPackData = parseJsonPayload(expoPackLoad);
    const expoPerPack = expoPackData.items_per_pack as Record<string, number>;
    assert(
      (expoPerPack?.["expo-rn"] ?? 0) >= 1,
      `expo multi-pack summary should include expo-rn items: ${JSON.stringify(expoPerPack)}`,
    );
    console.log("[smoke] expo multi-pack content coverage OK");

    const rnLibArch = await client.callTool({
      name: "secure_mcp_analyze_architecture",
      arguments: { project_root: rnLibFixture, response_format: "json" },
    });
    assert(!rnLibArch.isError, `rn-lib architecture failed: ${JSON.stringify(rnLibArch)}`);
    const rnLibData = parseJsonPayload(rnLibArch);
    const rnLibDetection = rnLibData.detection as Record<string, unknown>;
    assert(
      rnLibDetection?.hasExpo === false,
      `bare app.json + react-native dep must not set hasExpo: ${JSON.stringify(rnLibDetection)}`,
    );
    const rnLibPacks = rnLibData.recommended_packs as string[];
    assert(
      !rnLibPacks.includes("expo-rn"),
      `rn library fixture should not recommend expo-rn: ${rnLibPacks.join(",")}`,
    );
    console.log("[smoke] Expo detection false-positive guard OK");

    const expoAuth = await client.callTool({
      name: "secure_mcp_check_authentication",
      arguments: { project_root: expoFixture, response_format: "json" },
    });
    assert(!expoAuth.isError, `expo check_authentication failed: ${JSON.stringify(expoAuth)}`);
    const expoAuthData = parseJsonPayload(expoAuth);
    const expoAuthPacks = expoAuthData.applied_pack_ids as string[];
    assert(
      expoAuthPacks.includes("expo-rn"),
      `expo auth review should apply expo-rn: ${expoAuthPacks.join(",")}`,
    );
    assert(
      !expoAuthPacks.includes("auth-web"),
      `expo auth review should not claim auth-web: ${expoAuthPacks.join(",")}`,
    );
    console.log("[smoke] check_authentication Expo pack routing OK");

    const rnLibAuth = await client.callTool({
      name: "secure_mcp_check_authentication",
      arguments: { project_root: rnLibFixture, response_format: "json" },
    });
    assert(!rnLibAuth.isError, `rn-lib check_authentication failed: ${JSON.stringify(rnLibAuth)}`);
    const rnLibAuthData = parseJsonPayload(rnLibAuth);
    const rnLibAuthPacks = rnLibAuthData.applied_pack_ids as string[];
    assert(
      !rnLibAuthPacks.includes("expo-rn"),
      `rn-lib auth review should not apply expo-rn: ${rnLibAuthPacks.join(",")}`,
    );
    const rnLibAuthFindings = (rnLibAuthData.findings as Array<Record<string, unknown>>) ?? [];
    assert(
      !rnLibAuthFindings.some(
        (f) =>
          f.stack === "expo" ||
          String(f.title ?? "")
            .toLowerCase()
            .includes("mobile token storage"),
      ),
      `rn-lib auth review should not emit Expo findings: ${JSON.stringify(rnLibAuthFindings)}`,
    );
    console.log("[smoke] check_authentication rn-lib-no-expo routing OK");

    const packCategoryFilter = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: batches[0],
        categories: ["authentication"],
        detail: "summary",
        response_format: "json",
      },
    });
    assert(
      !packCategoryFilter.isError,
      `get_knowledge_pack category filter failed: ${JSON.stringify(packCategoryFilter)}`,
    );
    const categoryData = parseJsonPayload(packCategoryFilter);
    const categoryItems = categoryData.items as Array<Record<string, unknown>>;
    assert(categoryItems.length > 0, "Expected authentication items");
    assert(
      categoryItems.every((item) => String(item.category).toLowerCase() === "authentication"),
      "Category filter leaked other categories",
    );
    assert(
      categoryData.truncated_by_max_items === false,
      `category filter must not report max_items truncation: ${JSON.stringify(categoryData.truncated_by_max_items)}`,
    );
    console.log("[smoke] get_knowledge_pack category filter truncation flag OK");

    const packTruncated = await client.callTool({
      name: "secure_mcp_get_knowledge_pack",
      arguments: {
        pack_ids: ["core"],
        max_items: 2,
        detail: "summary",
        response_format: "json",
      },
    });
    assert(!packTruncated.isError, `get_knowledge_pack truncation failed: ${JSON.stringify(packTruncated)}`);
    const truncatedData = parseJsonPayload(packTruncated);
    assert(
      truncatedData.truncated_by_max_items === true,
      "max_items below available items should report truncation",
    );
    console.log("[smoke] get_knowledge_pack truncation flag OK");

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
