import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { threatEvidencePaths, threatModelPackIds } from "./buildRemediationThreatModel.js";

describe("threat model provenance", () => {
  it("derives threat-specific evidence paths instead of a global union", () => {
    const authThreat = threatEvidencePaths(
      {
        title: "Weak session or credential validation",
        related_components: [],
        stride: "S",
      },
      { api: ["app/api/search/route.ts"], auth: ["lib/auth.ts"], secrets: [".env"] },
    );
    const secretsThreat = threatEvidencePaths(
      {
        title: "Secrets or personal data exposed through code, logs, or client bundles",
        related_components: [],
        stride: "I",
      },
      { api: ["app/api/search/route.ts"], auth: ["lib/auth.ts"], secrets: [".env"] },
    );
    assert.deepEqual(authThreat, ["lib/auth.ts"]);
    assert.ok(secretsThreat.includes("[redacted-secret-file]"));
    assert.notDeepEqual(authThreat, secretsThreat);
  });

  it("makes applied pack ids stack-traceable", () => {
    const nextPacks = threatModelPackIds(["nextjs", "typescript"]);
    assert.ok(nextPacks.includes("threat-model"));
    assert.ok(nextPacks.includes("core"));
    assert.ok(nextPacks.includes("web-next") || nextPacks.includes("secrets"));

    const expoPacks = threatModelPackIds(["expo"]);
    assert.ok(expoPacks.includes("threat-model"));
    assert.ok(expoPacks.includes("core"));
    assert.ok(!expoPacks.includes("web-next"));
  });

  it("does not report component labels as observed paths without inventory support", () => {
    const threat = {
      title: "Incomplete Next.js boundary checks",
      related_components: ["middleware.ts", "app/api/**"],
      stride: "E" as const,
    };
    assert.deepEqual(
      threatEvidencePaths(threat, { api: [], auth: [], secrets: [] }, []),
      [],
    );
    assert.deepEqual(
      threatEvidencePaths(
        threat,
        { api: [], auth: [], secrets: [] },
        ["app/api/search/route.ts"],
      ),
      ["app/api/search/route.ts"],
    );
  });
});
