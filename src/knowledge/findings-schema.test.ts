import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  boundFinding,
  buildFinding,
  createFindingInstanceId,
  ensureFindingTraceability,
  FindingSchema,
  mergeFindings,
  MAX_FINDING_NARRATIVE,
  MAX_FINDING_TITLE,
  ProjectRootInput,
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

  it("preserves a traceability field through merge and post-redaction bounds", () => {
    const first = { ...sampleFinding(12), source: undefined };
    const second = {
      ...sampleFinding(12),
      source: "request.user.id",
      validation: ["Confirm the authenticated principal reaches the ownership check."],
    };

    const bounded = boundFinding(mergeFindings(first, second));

    assert.equal(bounded.source, second.source);
    assert.ok(bounded.validation?.includes(second.validation[0]!));
    assert.ok(bounded.validation?.includes(first.validation![0]!));
    assert.equal(FindingSchema.safeParse(bounded).success, true);
  });

});

describe("bounded finding payloads", () => {
  function oversizedFinding(overrides: Record<string, unknown> = {}) {
    return {
      ...sampleFinding(1),
      ...overrides,
    };
  }

  it("rejects oversized narrative strings at schema validation", () => {
    const result = FindingSchema.safeParse(
      oversizedFinding({ description: "d".repeat(MAX_FINDING_NARRATIVE + 1) }),
    );
    assert.equal(result.success, false);
  });

  it("rejects oversized title strings at schema validation", () => {
    const result = FindingSchema.safeParse(
      oversizedFinding({ title: "t".repeat(MAX_FINDING_TITLE + 1) }),
    );
    assert.equal(result.success, false);
  });

  it("rejects oversized nested string arrays", () => {
    const result = FindingSchema.safeParse(
      oversizedFinding({
        counterevidence: Array.from({ length: 21 }, (_, i) => `item-${i}`),
      }),
    );
    assert.equal(result.success, false);
  });

  it("rejects oversized tags arrays and tag strings", () => {
    const tooMany = FindingSchema.safeParse(
      oversizedFinding({ tags: Array.from({ length: 51 }, (_, i) => `tag-${i}`) }),
    );
    assert.equal(tooMany.success, false);
    const tooLong = FindingSchema.safeParse(oversizedFinding({ tags: ["x".repeat(201)] }));
    assert.equal(tooLong.success, false);
  });

  it("rejects oversized project_root and focus paths", () => {
    const rootResult = ProjectRootInput.safeParse({
      project_root: `/p/${"x".repeat(5_000)}`,
    });
    assert.equal(rootResult.success, false);
    const focusResult = ProjectRootInput.safeParse({
      project_root: "/tmp/repo",
      focus_paths: ["y".repeat(501)],
    });
    assert.equal(focusResult.success, false);
  });
});

describe("candidate dispositions", () => {
  it("accepts accepted_risk as a closed ledger disposition", () => {
    const finding = buildFinding({
      ...sampleFinding(12),
      disposition: "accepted_risk",
      disposition_reason: undefined,
    });
    assert.equal(finding.disposition, "accepted_risk");
    assert.match(finding.disposition_reason ?? "", /accept|residual|owner/i);
  });

  it("accepts fixed disposition for revalidated remediations", () => {
    const finding = buildFinding({
      ...sampleFinding(12),
      disposition: "fixed",
      disposition_reason: "Control added at source and verified in review.",
    });
    assert.equal(FindingSchema.safeParse(finding).success, true);
    assert.equal(finding.disposition, "fixed");
  });

  it("merges reportable over fixed when both exist for the same instance", () => {
    const fixed = buildFinding({
      ...sampleFinding(12),
      disposition: "fixed",
      disposition_reason: "Previously remediated.",
    });
    const open = buildFinding({
      ...sampleFinding(12),
      disposition: "reportable",
      disposition_reason: "Regression still open.",
    });
    const merged = mergeFindings(fixed, open);
    assert.equal(merged.disposition, "reportable");
    assert.equal(merged.disposition_reason, "Regression still open.");
  });

  it("keeps the fixed reason when no reportable candidate is merged", () => {
    const fixed = buildFinding({
      ...sampleFinding(12),
      disposition: "fixed",
      disposition_reason: "Control verified at sink.",
    });
    const needsReview = buildFinding({
      ...sampleFinding(12),
      disposition: "needs_review",
      disposition_reason: "Heuristic only.",
    });
    const merged = mergeFindings(fixed, needsReview);
    assert.equal(merged.disposition, "fixed");
    assert.equal(merged.disposition_reason, "Control verified at sink.");
  });

  it("never carries a losing disposition reason across merge orderings", () => {
    const cases = [
      {
        left: { disposition: "fixed" as const, disposition_reason: "Verified fixed." },
        right: { disposition: "reportable" as const, disposition_reason: undefined },
        expected: "reportable",
        reason: undefined,
      },
      {
        left: { disposition: "reportable" as const, disposition_reason: undefined },
        right: { disposition: "fixed" as const, disposition_reason: "Verified fixed." },
        expected: "reportable",
        reason: undefined,
      },
      {
        left: { disposition: "needs_review" as const, disposition_reason: "Proof incomplete." },
        right: { disposition: "deferred" as const, disposition_reason: "Owned backlog item." },
        expected: "needs_review",
        reason: "Proof incomplete.",
      },
      {
        left: { disposition: undefined, disposition_reason: "Unclassified prose." },
        right: { disposition: "deferred" as const, disposition_reason: "Owned backlog item." },
        expected: "deferred",
        reason: "Owned backlog item.",
      },
    ];

    for (const testCase of cases) {
      const left = { ...sampleFinding(12), ...testCase.left };
      const right = { ...sampleFinding(12), ...testCase.right };
      const merged = mergeFindings(left, right);
      assert.equal(merged.disposition, testCase.expected);
      assert.equal(merged.disposition_reason, testCase.reason);
    }

    const dispositions = ["reportable", "fixed", "needs_review", undefined] as const;
    for (const leftDisposition of dispositions) {
      for (const rightDisposition of dispositions) {
        const left = {
          ...sampleFinding(12),
          disposition: leftDisposition,
          disposition_reason: leftDisposition ? `left:${leftDisposition}` : undefined,
        };
        const right = {
          ...sampleFinding(12),
          disposition: rightDisposition,
          disposition_reason: rightDisposition ? `right:${rightDisposition}` : undefined,
        };
        const winner =
          leftDisposition === "reportable" || rightDisposition === "reportable"
            ? "reportable"
            : leftDisposition ?? rightDisposition;
        const expectedReason = [left, right].find(
          (finding) => finding.disposition === winner,
        )?.disposition_reason;

        const merged = mergeFindings(left, right);
        assert.equal(merged.disposition, winner);
        assert.equal(merged.disposition_reason, expectedReason);
      }
    }
  });

  it("uses disposition-aware default reasons", () => {
    const fixed = buildFinding({
      ...sampleFinding(12),
      disposition: "fixed",
      disposition_reason: undefined,
    });
    const deferred = buildFinding({
      ...sampleFinding(12),
      disposition: "deferred",
      disposition_reason: undefined,
    });

    assert.match(fixed.disposition_reason ?? "", /revalidation|remediation/i);
    assert.doesNotMatch(fixed.disposition_reason ?? "", /heuristic candidate/i);
    assert.match(deferred.disposition_reason ?? "", /deferred|open/i);
  });
});
