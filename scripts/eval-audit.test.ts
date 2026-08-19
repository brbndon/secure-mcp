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
  evidence?: string;
  severity?: string;
}

interface AuditSnapshot {
  stacks: string[];
  packs: string[];
  findings: FindingRef[];
  authz_gap_paths: string[];
  serialized_payloads: string[];
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
      coverage_gaps?: Array<{ paths?: string[]; authz_id?: string }>;
    };
    const authz_gap_paths = [
      ...new Set(
        (archData.coverage_gaps ?? [])
          .filter((gap) => Boolean(gap.authz_id))
          .flatMap((gap) => gap.paths ?? []),
      ),
    ];

    const serialized_payloads: string[] = [serializeToolResult(arch)];
    const findings: FindingRef[] = [];
    const produceInput: unknown[] = [];
    for (const tool of CATEGORY_TOOLS) {
      const result = await client.callTool({
        name: tool,
        arguments: { project_root: projectRoot, response_format: "json" },
      });
      assert.equal(result.isError, undefined, `${tool} failed for ${fixture}`);
      serialized_payloads.push(serializeToolResult(result));
      const data = result.structuredContent as { findings?: FindingRef[] };
      for (const finding of data.findings ?? []) findings.push(finding);
      if (tool === "secure_mcp_review_secrets") {
        produceInput.push(...(data.findings ?? []));
      }
    }

    if (produceInput.length > 0) {
      for (const format of ["json", "markdown", "sarif"] as const) {
        const report = await client.callTool({
          name: "secure_mcp_produce_findings",
          arguments: {
            project_root: projectRoot,
            findings: produceInput,
            response_format: format,
            report_title: `${fixture} secrets eval`,
          },
        });
        assert.equal(report.isError, undefined, `produce_findings ${format} failed for ${fixture}`);
        serialized_payloads.push(serializeToolResult(report));
      }
    }

    return {
      stacks: archData.stacks ?? [],
      packs: archData.recommended_packs ?? [],
      findings,
      authz_gap_paths,
      serialized_payloads,
    };
  } finally {
    await client.close();
    await server.close();
  }
}

function serializeToolResult(result: {
  structuredContent?: unknown;
  content?: unknown;
}): string {
  const text = Array.isArray(result.content)
    ? result.content
        .map((part) =>
          part && typeof part === "object" && "text" in part
            ? String((part as { text: string }).text)
            : "",
        )
        .join("\n")
    : "";
  return `${JSON.stringify(result.structuredContent ?? {})}\n${text}`;
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

    if (expectation.required_authz_gap_paths?.length) {
      it(`recalls expected authz coverage-gap paths (${fixture})`, () => {
        for (const gapPath of expectation.required_authz_gap_paths ?? []) {
          assert.ok(
            audit.authz_gap_paths.includes(gapPath),
            `missing authz coverage gap for "${gapPath}"; observed [${audit.authz_gap_paths.join(", ")}]`,
          );
        }
      });
    }

    it(`does not cite clean files (${fixture})`, () => {
      const cited = new Set(
        audit.findings.map((f) => f.file).filter((v): v is string => Boolean(v)),
      );
      for (const clean of expectation.clean_files ?? []) {
        assert.ok(!cited.has(clean), `clean file "${clean}" was cited as a finding location`);
      }
    });

    if (expectation.forbidden_raw_secrets?.length) {
      it(`never emits planted secret material (${fixture})`, () => {
        const combined = audit.serialized_payloads.join("\n");
        for (const secret of expectation.forbidden_raw_secrets ?? []) {
          assert.ok(
            !combined.includes(secret),
            `raw planted secret leaked into a tool payload: ${secret}`,
          );
        }
        const secretsFindings = audit.findings.filter(
          (finding) => finding.rule_family === "secrets.secret-patterns",
        );
        assert.ok(
          secretsFindings.length > 0,
          "secrets.secret-patterns recall floor failed before redaction check",
        );
        for (const finding of secretsFindings) {
          assert.ok(finding.evidence, "secrets candidate missing evidence");
          assert.match(
            finding.evidence ?? "",
            /REDACTED|\*{4}/,
            `secrets evidence was not redacted: ${finding.evidence}`,
          );
        }
      });
    }

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
