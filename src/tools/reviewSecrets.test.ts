import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  classifySecretPatternMatch,
  secretsPackIdsForStack,
  shouldRunNextjsSecretDetectors,
  shouldRunSwiftSecretDetectors,
} from "./reviewSecrets.js";

describe("secret-pattern false-positive classification", () => {
  it("suppresses ordinary sample matches but retains high-impact material at low confidence", () => {
    assert.deepEqual(
      classifySecretPatternMatch("GitHub token", "credential-shaped-value", "sample fixture"),
      { suppressed: true, confidence: "low" },
    );
    assert.deepEqual(
      classifySecretPatternMatch("AWS access key id", "credential-shaped-value", "sample fixture"),
      { suppressed: false, confidence: "low" },
    );
    assert.deepEqual(
      classifySecretPatternMatch("Private key block", "credential-shaped-value", "placeholder"),
      { suppressed: false, confidence: "low" },
    );
  });

  it("keeps unhinted matches visible at high confidence", () => {
    assert.deepEqual(
      classifySecretPatternMatch("Slack token", "credential-shaped-value", "production config"),
      { suppressed: false, confidence: "high" },
    );
  });
});

describe("secrets stack routing", () => {
  it("does not run or claim Next.js detectors for explicit expo or common focus", () => {
    assert.equal(shouldRunNextjsSecretDetectors("expo"), false);
    assert.equal(shouldRunNextjsSecretDetectors("common"), false);
    assert.equal(shouldRunNextjsSecretDetectors("swift"), false);
    assert.equal(shouldRunNextjsSecretDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsSecretDetectors("typescript"), false);
    assert.equal(shouldRunNextjsSecretDetectors("auto"), true);

    assert.deepEqual(secretsPackIdsForStack("expo"), ["core", "secrets"]);
    assert.deepEqual(secretsPackIdsForStack("common"), ["core", "secrets"]);
    assert.ok(!secretsPackIdsForStack("expo").includes("web-next"));
    assert.ok(secretsPackIdsForStack("nextjs").includes("web-next"));
    assert.ok(!secretsPackIdsForStack("typescript").includes("web-next"));
  });

  it("runs Swift secret detectors only for auto or swift focus", () => {
    assert.equal(shouldRunSwiftSecretDetectors("swift"), true);
    assert.equal(shouldRunSwiftSecretDetectors("auto"), true);
    assert.equal(shouldRunSwiftSecretDetectors("expo"), false);
    assert.equal(shouldRunSwiftSecretDetectors("nextjs"), false);
    assert.ok(secretsPackIdsForStack("swift").includes("swift-ios"));
    assert.ok(!secretsPackIdsForStack("expo").includes("swift-ios"));
  });
});
