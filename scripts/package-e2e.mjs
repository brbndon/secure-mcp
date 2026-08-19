/**
 * Nonpublishing end-to-end test for the npm fallback artifact.
 *
 * Builds and packs @brdndon/secure-mcp@2.0.0, installs the tarball into a
 * temporary consumer directory outside the repository, checks the bin, then
 * connects with the MCP v2 client pinned to protocol 2026-07-28 and calls a
 * filesystem tool against an explicitly allowlisted fixture.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  accessSync,
  constants,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  rmSync,
  statSync,
} from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixture = path.join(root, "fixtures", "tiny-app");
const PROJECT_VERSION = "2.0.0";
const MODERN_PROTOCOL_VERSION = "2026-07-28";
const REQUIRED_TOOLS = [
  "secure_mcp_list_project_structure",
  "secure_mcp_analyze_architecture",
  "secure_mcp_get_knowledge_pack",
  "secure_mcp_get_audit_guidance",
  "secure_mcp_check_authentication",
  "secure_mcp_analyze_injection_risks",
  "secure_mcp_review_secrets",
  "secure_mcp_build_remediation_threat_model",
  "secure_mcp_produce_findings",
  "secure_mcp_list_authorized_roots",
  "secure_mcp_list_projects",
  "secure_mcp_run_local_scanners",
];
const tempBase = mkdtempSync(path.join(os.tmpdir(), "secure-mcp-package-"));
const consumer = path.join(tempBase, "consumer");

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd ?? root,
    encoding: "utf8",
    maxBuffer: 64 * 1024 * 1024,
    env: { ...process.env, ...(options.env ?? {}) },
    stdio: options.stdio ?? "pipe",
  });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(" ")} failed (${result.status}):\n${result.error ?? ""}\n${result.stderr ?? ""}\n${result.stdout ?? ""}`,
    );
  }
  return result;
}

function lastJsonLine(stdout) {
  const lines = stdout.trim().split("\n");
  const start = lines.findIndex((line) => line.trim().startsWith("[") || line.trim().startsWith("{"));
  if (start < 0) throw new Error(`npm pack produced no JSON output:\n${stdout}`);
  return JSON.parse(lines.slice(start).join("\n"));
}

function assertNoSensitiveArtifacts(files) {
  const bannedPrefixes = ["src/", "fixtures/", "scripts/", ".agents/", "pages/", "docs/", ".github/", "node_modules/"];
  const bannedPatterns = [/\.env/, /\.local$/, /\.tgz$/, /server\.json$/];
  for (const file of files) {
    if (bannedPrefixes.some((prefix) => file.startsWith(prefix))) {
      throw new Error(`package must not contain ${file}`);
    }
    if (bannedPatterns.some((pattern) => pattern.test(file))) {
      throw new Error(`package must not contain ${file}`);
    }
  }
}

function assertNoPrivatePaths(directory) {
  const entries = readdirSync(directory, { withFileTypes: true });
  for (const entry of entries) {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) {
      assertNoPrivatePaths(full);
      continue;
    }
    if (/\.(js|js\.map|d\.ts|d\.ts\.map|json|md)$/.test(entry.name)) {
      const content = readFileSync(full, "utf8");
      assert.equal(content.includes(root), false, `package artifact embeds the local checkout path: ${full}`);
      assert.equal(content.includes(os.homedir()), false, `package artifact embeds a home-directory path: ${full}`);
    }
  }
}

async function connectConsumer(installedEntry) {
  const transport = new StdioClientTransport({
    command: process.execPath,
    args: [installedEntry],
    cwd: consumer,
    env: {
      ...process.env,
      SECURE_MCP_ALLOWED_ROOTS: fixture,
    },
  });
  const client = new Client(
    { name: "secure-mcp-package-e2e", version: PROJECT_VERSION },
    { versionNegotiation: { mode: { pin: MODERN_PROTOCOL_VERSION } } },
  );
  try {
    await client.connect(transport);
    assert.equal(client.getProtocolEra(), "modern");
    assert.equal(client.getNegotiatedProtocolVersion(), MODERN_PROTOCOL_VERSION);

    const listed = await client.listTools();
    assert.equal(listed.tools.length, REQUIRED_TOOLS.length);
    assert.deepEqual(
      new Set(listed.tools.map((tool) => tool.name)),
      new Set(REQUIRED_TOOLS),
    );

    const result = await client.callTool({
      name: "secure_mcp_list_project_structure",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert.notEqual(result.isError, true, JSON.stringify(result));
    const text = (result.content ?? [])
      .filter((part) => part && typeof part === "object" && "text" in part)
      .map((part) => part.text)
      .join("\n");
    assert.ok(text.length > 0);

    const secrets = await client.callTool({
      name: "secure_mcp_review_secrets",
      arguments: { project_root: fixture, response_format: "json" },
    });
    assert.notEqual(secrets.isError, true, JSON.stringify(secrets));
    const secretsText = `${JSON.stringify(secrets.structuredContent ?? {})}\n${(secrets.content ?? [])
      .filter((part) => part && typeof part === "object" && "text" in part)
      .map((part) => part.text)
      .join("\n")}`;
    assert.ok(
      !secretsText.includes("planted_secure_mcp_eval_api_key_value_123456"),
      "published bin must redact the planted eval API key",
    );
    const secretFindings = (secrets.structuredContent ?? {}).findings ?? [];
    assert.ok(
      secretFindings.some((finding) => finding.rule_family === "secrets.secret-patterns"),
      "published bin must recall secrets.secret-patterns on the tiny-app fixture",
    );
    return { tools: listed.tools.length, called: true };
  } finally {
    await client.close();
  }
}

try {
  assert.equal(
    JSON.parse(readFileSync(path.join(root, "package.json"), "utf8")).version,
    PROJECT_VERSION,
  );

  run("pnpm", ["build"]);

  const packed = run("npm", ["pack", "--json", "--pack-destination", tempBase]);
  const manifest = Array.isArray(packed.stdout.trim() ? lastJsonLine(packed.stdout) : null)
    ? lastJsonLine(packed.stdout)[0]
    : lastJsonLine(packed.stdout);
  assert.equal(manifest.name, "@brdndon/secure-mcp");
  assert.equal(manifest.version, PROJECT_VERSION);
  assert.ok(manifest.filename.endsWith(`-${PROJECT_VERSION}.tgz`), manifest.filename);
  assertNoSensitiveArtifacts(manifest.files.map((file) => file.path));

  const expectedFiles = ["package.json", "dist/index.js", "README.md", "LICENSE", "CHANGELOG.md", "NOTICE"];
  assert.ok(
    !manifest.files.some((file) => file.path.includes("SKILL.md") || file.path.startsWith("examples/")),
    "npm tarball must stay server-only: no skill and no examples drop-in",
  );
  for (const expected of expectedFiles) {
    assert.ok(
      manifest.files.some((file) => file.path === expected),
      `package missing intended artifact ${expected}`,
    );
  }

  const tarball = path.join(tempBase, manifest.filename);
  mkdirSync(consumer, { recursive: true });
  run("npm", ["install", "--no-audit", "--no-fund", "--loglevel=error", tarball], { cwd: consumer });

  const installedPackage = path.join(consumer, "node_modules", "@brdndon", "secure-mcp");
  const installedEntry = path.join(installedPackage, "dist", "index.js");
  assert.equal(JSON.parse(readFileSync(path.join(installedPackage, "package.json"), "utf8")).version, PROJECT_VERSION);
  assertNoPrivatePaths(installedPackage);

  const binShim = path.join(consumer, "node_modules", ".bin", "secure-mcp");
  const binWindows = path.join(consumer, "node_modules", ".bin", "secure-mcp.cmd");
  if (process.platform === "win32") {
    accessSync(binWindows, constants.F_OK);
  } else {
    accessSync(binShim, constants.X_OK);
    assert.notEqual(statSync(binShim).mode & 0o111, 0, "secure-mcp bin must be executable");
  }

  const summary = await connectConsumer(installedEntry);
  console.log(
    `[package-e2e] OK: ${manifest.filename} installed as consumer dependency, bin checked, ${summary.tools} tools listed, filesystem tool called over ${MODERN_PROTOCOL_VERSION}.`,
  );
} finally {
  rmSync(tempBase, { recursive: true, force: true });
}
