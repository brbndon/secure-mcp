/**
 * Capture real secure-mcp output for the marketing site gallery.
 * Spawns the actual server over stdio with a fixture-scoped filesystem allowlist,
 * runs the multi-phase audit tools against fixtures/tiny-app, and
 * writes path-sanitized output into pages/_home/captures/.
 *
 * Usage (from the repo root):
 *   node scripts/capture-output.mjs
 */
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";
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
const client = new Client({ name: "capture", version: "2.0.0" });
await client.connect(transport);

function textOf(result) {
  const t = (result.content ?? []).find((c) => c.type === "text");
  return t ? t.text : JSON.stringify(result);
}

const UNTRUSTED_BANNER_RE = /^\[secure-mcp\] UNTRUSTED AUDIT DATA:[^\n]*\n{1,2}/;

/**
 * Markdown-escape every character the server's escapeMarkdown() escapes so
 * paths embedded in rendered reports are sanitized too (e.g. `secure\-mcp`).
 */
function escapeMarkdownChars(value) {
  return value.replace(/[\\`*_{}\[\]()#+\-.!/|<>~:=;,]/g, (c) => `\\${c}`);
}

/** Sanitize absolute local paths out of captured output, failing loudly on any remnant. */
function sanitizeForPublic(text) {
  const publicRoot = "/workspace/secure-mcp";
  const variants = [
    root,
    root.replaceAll("/", "\\/"),
    escapeMarkdownChars(root),
  ];
  const replacements = [
    publicRoot,
    publicRoot.replaceAll("/", "\\/"),
    escapeMarkdownChars(publicRoot),
  ];
  let out = text;
  variants.forEach((variant, i) => {
    out = out.replaceAll(variant, replacements[i]);
  });
  const remnant = variants.find((variant) => out.includes(variant));
  if (remnant) {
    throw new Error(`capture sanitization failed: output still contains ${remnant}`);
  }
  // Catch any other home-directory form (plain or Markdown/JSON-escaped) even
  // if it does not exactly match the repo-root variants above.
  if (/\/Users\/[A-Za-z0-9._-]+\//.test(out) || /\\\/Users\\\/[A-Za-z0-9._-]+\\\//.test(out)) {
    throw new Error("capture sanitization failed: output still contains a /Users/<name>/ path");
  }
  return out;
}

async function save(name, result, { prettifyJson = false } = {}) {
  const text = sanitizeForPublic(textOf(result));
  let out = text;
  if (prettifyJson) {
    try {
      // Tool text starts with the untrusted-data banner; parse the JSON body
      // after it and keep the banner in the saved capture.
      const body = text.replace(UNTRUSTED_BANNER_RE, "");
      const prettified = JSON.stringify(JSON.parse(body), null, 2);
      out = text.startsWith("[secure-mcp] UNTRUSTED") ? `${text.match(UNTRUSTED_BANNER_RE)?.[0] ?? ""}${prettified}` : prettified;
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
