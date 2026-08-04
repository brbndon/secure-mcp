import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildFinding,
  createFindingInstanceId,
  ensureFindingTraceability,
  FindingSchema,
} from "./findings-schema.js";

function sampleFinding(line: number) {
  return buildFinding({
    id: `SESSION-${line}`,
    title: "Unsafe sink candidate",
    description: "A bounded detector observed a possible unsafe sink.",
    severity: "high",
    confidence: "medium",
    category: "injection-risk",
    file: "src/route.ts",
    line,
    evidence: "safe evidence summary",
    impact_if_unremediated: "The control gap may affect integrity.",
    remediation: "Use the approved safe API and validate input.",
    tags: ["INJ-SINK"],
  });
}

describe("finding traceability", () => {
  it("keeps the same instance identity across session ids and changes it by source location", () => {
    const first = sampleFinding(12);
    const second = { ...sampleFinding(12), id: "OTHER-999" };
    const moved = sampleFinding(13);

    assert.equal(first.rule_family, "injection-risk");
    assert.equal(first.root_control, "INJ-SINK");
    assert.equal(first.instance_id, second.instance_id);
    assert.notEqual(first.instance_id, moved.instance_id);
    assert.equal(
      first.instance_id,
      createFindingInstanceId({
        rule_family: "injection-risk",
        root_control: "INJ-SINK",
        file: "src/route.ts",
        line: 12,
      }),
    );
  });

  it("ignores free-form source/sink prose when hashing instance identity", () => {
    const base = {
      rule_family: "injection-risk",
      root_control: "INJ-SINK",
      file: "src/route.ts",
      line: 12,
    };
    assert.equal(
      createFindingInstanceId({ ...base, source: "prose A", sink: "sink A" }),
      createFindingInstanceId({ ...base, source: "prose B", sink: "sink B" }),
    );
    assert.notEqual(
      createFindingInstanceId(base),
      createFindingInstanceId({ ...base, line: 99 }),
    );
  });

  it("recomputes identity instead of trusting a caller-supplied instance id", () => {
    const finding = buildFinding({
      ...sampleFinding(12),
      instance_id: "caller-controlled-id",
    });
    assert.notEqual(finding.instance_id, "caller-controlled-id");
    assert.equal(
      finding.instance_id,
      createFindingInstanceId({
        rule_family: finding.rule_family!,
        root_control: finding.root_control!,
        file: finding.file,
        line: finding.line,
      }),
    );
  });

  it("adds additive traceability to a legacy finding without changing its required fields", () => {
    const legacy = {
      id: "OLD-1",
      title: "Legacy candidate",
      description: "Legacy description",
      severity: "low" as const,
      confidence: "low" as const,
      category: "configuration",
      evidence: "configuration key",
      impact_if_unremediated: "Configuration drift may persist.",
      remediation: "Review the configuration.",
      residual_risk: "Review remains necessary.",
      verification_suggestion: "Run the configuration check.",
    };
    const enriched = ensureFindingTraceability(legacy);
    assert.equal(FindingSchema.safeParse(enriched).success, true);
    assert.equal(enriched.disposition, "needs_review");
    assert.ok(enriched.instance_id);
    assert.ok(enriched.proof_gap?.length);
    assert.ok(enriched.validation?.length);
  });

});
