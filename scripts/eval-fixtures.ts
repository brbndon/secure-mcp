/**
 * Eval fixture metadata for scripts/eval-audit.test.ts.
 *
 * This is the "labeled expected candidate families" contract for the offline
 * recall/precision smoke harness. It intentionally tests detector *families*,
 * not full CVE theater: a recall floor asserts that a known, planted weakness
 * surfaces as a candidate; a precision smoke asserts that a clean or
 * differently-stacked fixture does not spam cross-stack or false positives.
 *
 * Interpretation (see docs/docs/eval-harness.md):
 * - `required_rule_families` / `required_categories` must all be observed in
 *   at least one candidate finding across the category tools for the fixture.
 *   A miss is a recall regression (a known weakness stopped surfacing).
 * - `forbidden_rule_families` / `forbidden_packs` must never be observed for
 *   the fixture. A hit is a stack-isolation or false-positive regression.
 * - `clean_files` must not be cited as a finding location.
 * - `expect_zero_findings` asserts a known-clean library fixture produces no
 *   candidates at all.
 *
 * Do not add offensive or exploit content. These are defensive heuristics.
 */

export interface EvalFixtureExpectation {
  /** Detected stack labels that must be present (subset check, in any order). */
  stacks_include?: string[];
  /** Candidate rule_family values that must appear (recall floor). */
  required_rule_families: string[];
  /** Candidate categories that must appear (recall floor). */
  required_categories: string[];
  /** Candidate rule_family values that must NOT appear (precision smoke). */
  forbidden_rule_families?: string[];
  /** Recommended pack ids that must NOT appear (precision smoke). */
  forbidden_packs?: string[];
  /** Fixture-relative file paths that must not be cited as a finding location. */
  clean_files?: string[];
  /** Architecture authz coverage-gap paths that must appear (recall floor). */
  required_authz_gap_paths?: string[];
  /**
   * Planted credential strings that must never appear in any tool payload
   * (structured JSON, markdown, SARIF, notes, or coverage paths).
   */
  forbidden_raw_secrets?: string[];
  /** When true, all category tools must return zero findings. */
  expect_zero_findings?: boolean;
  /** Human-readable note explaining the fixture and its expectations. */
  notes: string;
}

export const EVAL_FIXTURES: Record<string, EvalFixtureExpectation> = {
  "tiny-app": {
    stacks_include: ["nextjs"],
    required_rule_families: [
      "secrets.secret-patterns",
      "core.injection",
      "web-next.authentication",
      "core.authorization",
    ],
    required_categories: ["secrets", "injection-risk", "authentication", "authorization"],
    required_authz_gap_paths: ["app/api/users/[id]/route.ts"],
    forbidden_raw_secrets: [
      "planted_secure_mcp_eval_api_key_value_123456",
      "hardcoded_swift_api_key_value_123456",
      "super-secret-hardcoded-jwt-key-12345",
    ],
    forbidden_rule_families: ["expo-rn.profile-auth-storage"],
    forbidden_packs: ["expo-rn"],
    notes:
      "Next.js app with planted weaknesses (hardcoded JWT, non-vendor planted API key, Swift apiKey, shell/SQL/redirect injection, incomplete middleware auth, dynamic [id] route without object-level authorization). Also contains ios/Secrets.swift, so swift families may legitimately appear under mixed detection — that is expected union behavior, not a regression.",
  },
  "tiny-expo": {
    stacks_include: ["expo"],
    required_rule_families: ["expo-rn.profile-auth-storage"],
    required_categories: ["authentication"],
    forbidden_rule_families: [
      "web-next.authentication",
      "web-next.injection",
      "swift-ios.secret-handling",
    ],
    forbidden_packs: ["web-next", "swift-ios", "auth-web"],
    notes:
      "App-only Expo fixture (app.json + package.json, no source files). Recall floor is the expo auth-storage profile candidate; precision asserts no Next/Swift packs or detectors leak in.",
  },
  "tiny-swift": {
    stacks_include: ["swift"],
    required_rule_families: [
      "swift-ios.secret-handling",
      "swift-ios.authentication",
      "secrets.secret-patterns",
    ],
    required_categories: ["secrets", "authentication"],
    forbidden_rule_families: ["web-next.authentication", "expo-rn.profile-auth-storage"],
    forbidden_packs: ["web-next", "expo-rn"],
    clean_files: ["Sources/DemoApp/SafeBits.swift"],
    notes:
      "Swift package with planted weaknesses (hardcoded password, pasteboard, print-log, keychain always-accessible, ATS cleartext). SafeBits.swift is a known-clean file that must not be cited.",
  },
  "rn-lib-no-expo": {
    stacks_include: ["typescript"],
    required_rule_families: [],
    required_categories: [],
    forbidden_rule_families: [
      "expo-rn.profile-auth-storage",
      "web-next.authentication",
      "swift-ios.authentication",
    ],
    forbidden_packs: ["expo-rn", "swift-ios"],
    expect_zero_findings: true,
    notes:
      "React Native library with a non-Expo app.json. Must not route to expo-rn or emit any candidates; proves library/dev-tool honesty and zero false-positive spam on a clean tree.",
  },
};
