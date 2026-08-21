/**
 * Drift guard for the published Finding JSON Schema artifact.
 *
 * schemas/finding.schema.json must always equal what Zod generates from
 * src/knowledge/findings-schema.ts today. A failure means the Finding
 * contract changed: regenerate with `pnpm gen:schemas`, review the diff as a
 * compatibility-relevant change, and update the changelog before committing.
 *
 * Run: pnpm exec tsx --test scripts/finding-schema-artifact.test.ts
 */

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { renderFindingSchemaArtifact } from "./gen-schemas.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const artifactPath = path.join(repoRoot, "schemas", "finding.schema.json");

/** Fields the tool-design compatibility policy declares stable and required. */
const REQUIRED_FINDING_FIELDS = [
  "evidence",
  "severity",
  "confidence",
  "category",
  "impact_if_unremediated",
  "remediation",
  "residual_risk",
  "verification_suggestion",
] as const;

describe("finding.schema.json artifact", () => {
  it("matches the schema generated from the current Zod source", async () => {
    const committed = await readFile(artifactPath, "utf8");
    assert.equal(
      renderFindingSchemaArtifact(),
      committed,
      "committed schemas/finding.schema.json is stale; run pnpm gen:schemas and review the diff",
    );
  });

  it("advertises every stable required remediation field", async () => {
    const committed = JSON.parse(await readFile(artifactPath, "utf8")) as {
      required?: string[];
    };
    const required = new Set(committed.required ?? []);
    for (const field of REQUIRED_FINDING_FIELDS) {
      assert.ok(required.has(field), `generated schema is missing required field: ${field}`);
    }
  });

  it("keeps traceability fields optional", async () => {
    const committed = JSON.parse(await readFile(artifactPath, "utf8")) as {
      required?: string[];
      properties?: Record<string, unknown>;
    };
    const required = new Set(committed.required ?? []);
    assert.ok(committed.properties?.instance_id, "instance_id missing from properties");
    assert.ok(!required.has("instance_id"), "instance_id must stay optional (additive contract)");
    assert.ok(committed.properties?.disposition, "disposition missing from properties");
    assert.ok(!required.has("disposition"), "disposition must stay optional (additive contract)");
  });
});
