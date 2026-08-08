/**
 * Capture real secure-mcp output for the marketing site gallery.
 * Spawns the actual server over stdio with a fixture-scoped filesystem allowlist,
 * runs the multi-phase audit tools against fixtures/tiny-app, and
 * writes path-sanitized output into pages/_home/captures/.
 *
 * Usage (from the repo root):
 *   node scripts/capture-output.mjs
 */
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { writeFileSync, mkdirSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const fixture = path.join(root, "fixtures", "tiny-app");
const outDir = path.join(root, "pages", "_home", "captures");
mkdirSync(outDir, { recursive: true });

const env = {
  ...process.env,
  SECURE_MCP_ALLOWED_ROOTS: fixture,
};

const transport = new StdioClientTransport({
  command: "pnpm",
  args: ["exec", "tsx", "src/index.ts"],
  cwd: root,
  env,
});
const client = new Client({ name: "capture", version: "1.0.0" });
await client.connect(transport);

function textOf(result) {
  const t = (result.content ?? []).find((c) => c.type === "text");
  return t ? t.text : JSON.stringify(result);
}

async function save(name, result, { prettifyJson = false } = {}) {
  const publicRoot = "/workspace/secure-mcp";
  const text = textOf(result)
    .replaceAll(root, publicRoot)
    .replaceAll(root.replaceAll("/", "\\/"), publicRoot.replaceAll("/", "\\/"));
  let out = text;
  if (prettifyJson) {
    try {
      out = JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      // keep raw text for non-JSON payloads
    }
  }
  writeFileSync(path.join(outDir, name), out);
  console.log("wrote", name, `(${out.length} chars)`);
}

// 1. Inventory + coverage
const structure = await client.callTool({
  name: "secure_mcp_list_project_structure",
  arguments: { project_root: fixture, response_format: "json" },
});
await save("01-inventory.json", structure, { prettifyJson: true });

// 2. Knowledge pack summary (stack-aware guidance)
const pack = await client.callTool({
  name: "secure_mcp_get_knowledge_pack",
  arguments: {
    pack_ids: ["core", "secrets", "web-next", "auth-web", "web-api"],
    detail: "summary",
    max_items: 8,
    response_format: "json",
  },
});
await save("03-knowledge-pack.json", pack, { prettifyJson: true });

// 3. Secrets review — structured findings (evidence redacted)
const secrets = await client.callTool({
  name: "secure_mcp_review_secrets",
  arguments: { project_root: fixture, response_format: "json" },
});
await save("04-secrets.json", secrets, { prettifyJson: true });

// 4. Remediation report (markdown) — the bundled fixture is intentionally
// vulnerable, so promote its manually known candidates before report rollup.
const structuredFindings = secrets.structuredContent?.findings;
const findings = Array.isArray(structuredFindings)
  ? structuredFindings.map((finding) => ({
      ...finding,
      disposition: "reportable",
      disposition_reason: "Confirmed in the intentionally vulnerable bundled fixture.",
    }))
  : [];
const report = await client.callTool({
  name: "secure_mcp_produce_findings",
  arguments: {
    project_root: fixture,
    report_title: "tiny-app — secure code review (remediation)",
    min_severity: "low",
    min_confidence: "medium",
    dedupe: true,
    response_format: "markdown",
    findings,
  },
});
await save("05-report.md", report);

await client.close();
console.log("capture complete — refresh the homepage gallery");
