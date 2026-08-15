/**
 * Offline fixture eval harness: recall floor + precision smoke.
 *
 * Drives the real MCP server in-memory (no network, no spawned process) across
 * the fixtures listed in scripts/eval-fixtures.ts and asserts:
 *   - recall floor: planted weaknesses surface as candidate families/categories;
 *   - precision smoke: known-clean or differently-stacked fixtures do not emit
 *     cross-stack families, recommend wrong packs, or cite clean files.
 *
 * Run:
 *   pnpm exec tsx --test scripts/eval-audit.test.ts
 *
 * Interpreting failures: see docs/docs/eval-harness.md. A recall miss means a
 * detector stopped surfacing a planted weakness; a precision hit means a
 * stack-isolation or false-positive regression.
 */

import assert from "node:assert/strict";
import { before, describe, it } from "node:test";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../src/server.js";
import { EVAL_FIXTURES } from "./eval-fixtures.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const fixturesRoot = path.join(root, "fixtures");

const CATEGORY_TOOLS = [
  "secure_mcp_check_authentication",
  "secure_mcp_analyze_injection_risks",
  "secure_mcp_review_secrets",
] as const;

interface FindingRef {
  title?: string;
  rule_family?: string;
  category?: string;
  file?: string;
}

interface AuditSnapshot {
  stacks: string[];
  packs: string[];
  findings: FindingRef[];
}

async function runAudit(fixture: string): Promise<AuditSnapshot> {
  const projectRoot = path.join(fixturesRoot, fixture);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer({
    name: "secure-mcp-eval",
    version: "test",
    defaultMaxFiles: 400,
    maxFileBytes: 256 * 1024,
    maxDepth: 12,
    allowedRoots: [fixturesRoot],
  });
  const client = new Client({ name: "secure-mcp-eval-client", version: "test" });
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  try {
    const arch = await client.callTool({
      name: "secure_mcp_analyze_architecture",
      arguments: { project_root: projectRoot, response_format: "json" },
    });
    assert.equal(arch.isError, undefined, `analyze_architecture failed for ${fixture}`);
    const archData = arch.structuredContent as {
      stacks?: string[];
      recommended_packs?: string[];
    };

    const findings: FindingRef[] = [];
    for (const tool of CATEGORY_TOOLS) {
      const result = await client.callTool({
        name: tool,
        arguments: { project_root: projectRoot, response_format: "json" },
      });
      assert.equal(result.isError, undefined, `${tool} failed for ${fixture}`);
      const data = result.structuredContent as { findings?: FindingRef[] };
      for (const finding of data.findings ?? []) findings.push(finding);
    }

    return {
      stacks: archData.stacks ?? [],
      packs: archData.recommended_packs ?? [],
      findings,
    };
  } finally {
    await client.close();
    await server.close();
  }
}

function familiesOf(findings: readonly FindingRef[]): Set<string> {
  return new Set(findings.map((f) => f.rule_family).filter((v): v is string => Boolean(v)));
}

function categoriesOf(findings: readonly FindingRef[]): Set<string> {
  return new Set(findings.map((f) => f.category).filter((v): v is string => Boolean(v)));
}

for (const [fixture, expectation] of Object.entries(EVAL_FIXTURES)) {
  describe(`eval fixture: ${fixture}`, () => {
    let audit: AuditSnapshot;

    before(async () => {
      audit = await runAudit(fixture);
    });

    it(`recalls expected stacks (${fixture})`, () => {
      for (const stack of expectation.stacks_include ?? []) {
        assert.ok(
          audit.stacks.includes(stack),
          `expected stack "${stack}" in [${audit.stacks.join(", ")}]`,
        );
      }
    });

    it(`recalls expected candidate rule families (${fixture})`, () => {
      const observed = familiesOf(audit.findings);
      for (const family of expectation.required_rule_families) {
        assert.ok(
          observed.has(family),
          `missing required rule_family "${family}"; observed [${[...observed].sort().join(", ")}]`,
        );
      }
    });

    it(`recalls expected candidate categories (${fixture})`, () => {
      const observed = categoriesOf(audit.findings);
      for (const category of expectation.required_categories) {
        assert.ok(
          observed.has(category),
          `missing required category "${category}"; observed [${[...observed].sort().join(", ")}]`,
        );
      }
    });

    it(`does not emit forbidden rule families (${fixture})`, () => {
      const observed = familiesOf(audit.findings);
      for (const family of expectation.forbidden_rule_families ?? []) {
        assert.ok(!observed.has(family), `unexpected forbidden rule_family "${family}"`);
      }
    });

    it(`does not recommend forbidden packs (${fixture})`, () => {
      for (const pack of expectation.forbidden_packs ?? []) {
        assert.ok(
          !audit.packs.includes(pack),
          `unexpected recommended pack "${pack}" in [${audit.packs.join(", ")}]`,
        );
      }
    });

    it(`does not cite clean files (${fixture})`, () => {
      const cited = new Set(
        audit.findings.map((f) => f.file).filter((v): v is string => Boolean(v)),
      );
      for (const clean of expectation.clean_files ?? []) {
        assert.ok(!cited.has(clean), `clean file "${clean}" was cited as a finding location`);
      }
    });

    if (expectation.expect_zero_findings) {
      it(`produces zero candidate findings (${fixture})`, () => {
        assert.equal(
          audit.findings.length,
          0,
          `expected zero findings, got ${audit.findings.length}: ${JSON.stringify(
            audit.findings.map((f) => f.title ?? f.rule_family),
          )}`,
        );
      });
    }
  });
}
