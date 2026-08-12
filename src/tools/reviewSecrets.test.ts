import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { detectWithBudget, snippetAround } from "../lib/filesystem.js";
import { SECRET_PATTERNS } from "../knowledge/common.js";
import {
  FALSE_POSITIVE_HINTS,
  secretsPackIdsForStack,
  shouldRunNextjsSecretDetectors,
  shouldRunSwiftSecretDetectors,
} from "./reviewSecrets.js";

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

describe("false-positive placeholder suppression", () => {
  // Content mirrors fixtures/fake-placeholders/.env.example — the placeholder
  // strings developers commonly write when publishing a template env file.
  const FIXTURE_CONTENT = `
API_KEY=YOUR_API_KEY_HERE
SECRET_KEY=YOUR_SECRET_KEY_HERE
ACCESS_TOKEN=YOUR_ACCESS_TOKEN_HERE
AUTH_TOKEN=YOUR_AUTH_TOKEN_HERE
GITHUB_TOKEN=YOUR_GITHUB_TOKEN_HERE
STRIPE_SECRET_KEY=your-stripe-secret-key
DATABASE_PASSWORD=changeme
JWT_SECRET=changeme
SENDGRID_API_KEY=YOUR_SENDGRID_API_KEY_HERE
PRIVATE_KEY=your_private_key_here
REPLACE_ME_TOKEN=replace_me
SOME_SECRET=placeholder
`.trim();

  it("FALSE_POSITIVE_HINTS matches all common placeholder values", () => {
    const placeholders = [
      "YOUR_API_KEY_HERE",
      "YOUR_SECRET_KEY_HERE",
      "YOUR_ACCESS_TOKEN_HERE",
      "YOUR_AUTH_TOKEN_HERE",
      "YOUR_GITHUB_TOKEN_HERE",
      "your-stripe-secret-key",
      "changeme",
      "YOUR_SENDGRID_API_KEY_HERE",
      "your_private_key_here",
      "replace_me",
      "placeholder",
    ];
    for (const value of placeholders) {
      assert.ok(
        FALSE_POSITIVE_HINTS.test(value),
        `Expected FALSE_POSITIVE_HINTS to match placeholder: ${value}`,
      );
    }
  });

  it("produces no high-confidence findings when scanning only placeholder values", () => {
    // Replicate the detection logic from registerReviewSecrets so we can test
    // the suppression behaviour without hitting the filesystem.
    const highConfidenceFindings: { name: string; match: string; confidence: string }[] = [];

    for (const pattern of SECRET_PATTERNS) {
      for (const hit of detectWithBudget(pattern.regex, FIXTURE_CONTENT)) {
        const full = hit.match;
        const nearFp =
          FALSE_POSITIVE_HINTS.test(full) ||
          FALSE_POSITIVE_HINTS.test(snippetAround(FIXTURE_CONTENT, hit.index, 40));

        // Non-Private-key / non-AWS patterns are skipped entirely when nearFp.
        // AWS / Private-key patterns are kept but downgraded to low confidence.
        if (nearFp && !pattern.name.includes("Private key") && !pattern.name.includes("AWS")) {
          continue;
        }

        const confidence = nearFp ? "low" : "high";
        if (confidence === "high") {
          highConfidenceFindings.push({ name: pattern.name, match: full, confidence });
        }
      }
    }

    assert.equal(
      highConfidenceFindings.length,
      0,
      `Expected no high-confidence findings for placeholder fixture, got: ${JSON.stringify(highConfidenceFindings, null, 2)}`,
    );
  });
});
