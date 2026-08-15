/**
 * Invariant tests for the shared secret-token catalog.
 *
 * Every detector shape must have representative samples that the output seam
 * redacts. The redactor may intentionally cover additional conservative shapes
 * that are not detector findings; those output-only guarantees are tested
 * separately below.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { SECRET_PATTERNS } from "../knowledge/common.js";
import { redactedEvidence } from "./redact.js";
import {
  AWS_ACCESS_KEY_ID_SHAPE,
  GITHUB_TOKEN_SHAPE,
  JWT_LIKE_TOKEN_SHAPE,
  SECRET_TOKEN_SHAPES,
  SLACK_TOKEN_SHAPE,
  STRIPE_SECRET_KEY_SHAPE,
  type SecretTokenShape,
} from "./secret-tokens.js";

const SHAPE_SAMPLES = new Map<SecretTokenShape, readonly string[]>([
  [AWS_ACCESS_KEY_ID_SHAPE, [`AKIA${"A".repeat(16)}`]],
  [
    GITHUB_TOKEN_SHAPE,
    [
      `ghp_${"A".repeat(20)}`,
      `gho_${"A".repeat(20)}`,
      `ghu_${"A".repeat(20)}`,
      `ghs_${"A".repeat(20)}`,
      `ghr_${"A".repeat(20)}`,
      `github_pat_${"A".repeat(20)}`,
    ],
  ],
  [
    SLACK_TOKEN_SHAPE,
    ["b", "a", "p", "r", "s"].map((subtype) => `xox${subtype}-${"A".repeat(10)}`),
  ],
  [STRIPE_SECRET_KEY_SHAPE, [`sk_live_${"A".repeat(16)}`]],
  [JWT_LIKE_TOKEN_SHAPE, [`eyJ${"A".repeat(10)}.${"B".repeat(10)}.${"C".repeat(10)}`]],
]);

function matches(regex: RegExp, value: string): boolean {
  regex.lastIndex = 0;
  return regex.test(value);
}

describe("shared secret-token catalog", () => {
  it("requires detector and redaction samples for every catalog shape", () => {
    assert.equal(SHAPE_SAMPLES.size, SECRET_TOKEN_SHAPES.length);

    for (const shape of SECRET_TOKEN_SHAPES) {
      const samples = SHAPE_SAMPLES.get(shape);
      assert.ok(samples?.length, `missing samples for ${shape.name}`);
      assert.equal(shape.regex.global, true, `${shape.name} detector must be global`);
      assert.equal(
        (shape.redactionRegex ?? shape.regex).global,
        true,
        `${shape.name} redactor must be global`,
      );

      for (const sample of samples) {
        assert.equal(matches(shape.regex, sample), true, `detector must cover ${shape.name}`);
        const safe = redactedEvidence(`prefix ${sample} suffix`);
        assert.equal(safe.includes(sample), false, `redactor must cover ${shape.name}`);
        assert.match(safe, /REDACTED/);
      }
    }
  });

  it("uses the shared shape objects in the legacy detector order", () => {
    assert.deepEqual(
      SECRET_PATTERNS.map((pattern) => pattern.name),
      [
        "AWS access key id",
        "Generic API key assignment",
        "JWT-like token",
        "Private key block",
        "GitHub token",
        "Slack token",
        "Stripe secret key",
        "Password assignment",
      ],
    );
    for (const shape of SECRET_TOKEN_SHAPES) {
      assert.equal(
        SECRET_PATTERNS.find((pattern) => pattern.name === shape.name),
        shape,
        `SECRET_PATTERNS must reuse ${shape.name}`,
      );
    }
  });

  it("preserves detector thresholds while keeping redaction a safe superset", () => {
    const lowercaseAws = `akia${"a".repeat(16)}`;
    assert.equal(matches(AWS_ACCESS_KEY_ID_SHAPE.regex, lowercaseAws), false);
    assert.notEqual(redactedEvidence(lowercaseAws), lowercaseAws);

    assert.equal(matches(GITHUB_TOKEN_SHAPE.regex, `ghp_${"A".repeat(19)}`), false);
    assert.equal(matches(GITHUB_TOKEN_SHAPE.regex, `ghp_${"A".repeat(20)}`), true);
    assert.equal(matches(GITHUB_TOKEN_SHAPE.regex, `github_pat${"A".repeat(20)}`), false);
    assert.equal(matches(GITHUB_TOKEN_SHAPE.regex, `github_pat_${"A".repeat(12)}`), true);

    const shortSlack = `xoxb-${"A".repeat(9)}`;
    const minimumSlack = `xoxb-${"A".repeat(10)}`;
    assert.equal(matches(SLACK_TOKEN_SHAPE.regex, shortSlack), false);
    assert.equal(matches(SLACK_TOKEN_SHAPE.regex, minimumSlack), true);
    assert.notEqual(redactedEvidence(minimumSlack), minimumSlack);

    const shortStripe = `sk_live_${"A".repeat(15)}`;
    const minimumStripe = `sk_live_${"A".repeat(16)}`;
    assert.equal(matches(STRIPE_SECRET_KEY_SHAPE.regex, shortStripe), false);
    assert.equal(matches(STRIPE_SECRET_KEY_SHAPE.regex, minimumStripe), true);
    assert.notEqual(redactedEvidence(shortStripe), shortStripe);

    const shortJwt = `eyJ${"A".repeat(9)}.${"B".repeat(10)}.${"C".repeat(10)}`;
    assert.equal(matches(JWT_LIKE_TOKEN_SHAPE.regex, shortJwt), false);
  });

  it("preserves explicit output-only masking and stable empty/already-redacted input", () => {
    for (const value of [
      `ghp${"A".repeat(12)}`,
      `sk_test_${"A".repeat(12)}`,
      `pk_${"A".repeat(12)}`,
    ]) {
      assert.notEqual(redactedEvidence(value), value);
    }
    assert.equal(redactedEvidence(""), "");
    assert.equal(redactedEvidence("[REDACTED:****]"), "[REDACTED:****]");
  });
});
