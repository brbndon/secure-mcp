import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  redactCoverageReport,
  redactFinding,
  redactedEvidence,
  redactedSecretPath,
  redactedSecretPaths,
} from "./redact.js";
import type { CoverageReport, Finding } from "./types.js";

describe("secret evidence redaction", () => {
  it("removes secret-like values from evidence snippets", () => {
    const raw = 'const token = "super-secret-value-123456"; Authorization: Bearer abcdefghijklmnop AKIA1234567890ABCDEF';
    const safe = redactedEvidence(raw);
    assert.ok(!safe.includes("super-secret-value-123456"));
    assert.ok(!safe.includes("abcdefghijklmnop"));
    assert.ok(!safe.includes("AKIA1234567890ABCDEF"));
    assert.match(safe, /REDACTED/);
  });

  it("redacts whole PEM blocks including body material before BEGIN-only fallbacks", () => {
    const pem = [
      "-----BEGIN RSA PRIVATE KEY-----",
      "MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/SECRETKEYMATERIALHERE1234567890",
      "MORESECRETBASE64LINESTHATMUSTNOTLEAKINTHEOUTPUTABCDEFGHIJKLMN",
      "-----END RSA PRIVATE KEY-----",
    ].join("\n");
    const safe = redactedEvidence(`key material:\n${pem}\nend`);
    assert.ok(!safe.includes("SECRETKEYMATERIALHERE"));
    assert.ok(!safe.includes("MORESECRETBASE64"));
    assert.ok(!safe.includes("MIIEowIBAAKCAQEA"));
    assert.match(safe, /REDACTED/);
  });

  it("redacts secret-like evidence paths but preserves ordinary source paths", () => {
    assert.equal(redactedSecretPath("src/auth/session.ts"), "src/auth/session.ts");
    assert.equal(redactedSecretPath("config/.env.production"), "config/[redacted-secret-file]");
    assert.equal(redactedSecretPath("keys/service-account.json"), "keys/[redacted-secret-file]");
    assert.equal(redactedSecretPath("certs/server.pem"), "certs/[redacted-secret-file]");
    assert.deepEqual(redactedSecretPaths(["src/a.ts", ".env"]), [
      "src/a.ts",
      "[redacted-secret-file]",
    ]);
  });

  it("redacts secret paths embedded in evidence and location suffixes", () => {
    const safe = redactedEvidence(
      "source=config/.env.production:3; sink=keys/service-account.json:12:4; ordinary=src/auth.ts:9",
    );
    assert.ok(!safe.includes(".env.production"));
    assert.ok(!safe.includes("service-account.json"));
    assert.match(safe, /config\/\[redacted-secret-file\]:3/);
    assert.match(safe, /keys\/\[redacted-secret-file\]:12:4/);
    assert.ok(safe.includes("src/auth.ts:9"));
  });

  it("redacts finding evidence fields at the output boundary", () => {
    const finding: Finding = {
      id: "SEC-001",
      title: 'Hardcoded secret token = "super-secret-value-123456"',
      description: 'token = "super-secret-value-123456"',
      severity: "high",
      confidence: "medium",
      category: "secrets",
      file: "config/.env",
      line: 3,
      evidence: "-----BEGIN PRIVATE KEY-----\nLEAKEDBODY\n-----END PRIVATE KEY-----",
      impact_if_unremediated: 'Exposure of token = "super-secret-value-123456" may leak credentials.',
      remediation: 'Rotate token = "super-secret-value-123456" and remove from source.',
      residual_risk: 'History may retain token = "super-secret-value-123456".',
      verification_suggestion: 'Confirm token = "super-secret-value-123456" is gone after rotation.',
      disposition_reason: 'Observed token = "super-secret-value-123456" in config.',
      source: "Bearer abcdefghijklmnop",
      sink: "config/.env:3",
      instance_id: "secrets:stable",
    };
    const safe = redactFinding(finding);
    assert.equal(safe.file, "config/[redacted-secret-file]");
    assert.ok(!safe.evidence.includes("LEAKEDBODY"));
    assert.ok(!safe.description.includes("super-secret-value-123456"));
    assert.ok(!safe.title.includes("super-secret-value-123456"));
    assert.ok(!safe.remediation.includes("super-secret-value-123456"));
    assert.ok(!safe.impact_if_unremediated.includes("super-secret-value-123456"));
    assert.ok(!safe.residual_risk.includes("super-secret-value-123456"));
    assert.ok(!safe.verification_suggestion.includes("super-secret-value-123456"));
    assert.ok(!safe.disposition_reason?.includes("super-secret-value-123456"));
    assert.match(safe.title, /REDACTED/);
    assert.match(safe.remediation, /REDACTED/);
    assert.ok(!safe.source?.includes("abcdefghijklmnop"));
    assert.equal(safe.instance_id, "secrets:stable");
    assert.equal(safe.id, "SEC-001");
    assert.equal(safe.line, 3);
  });

  it("redacts secret-like paths on coverage reports", () => {
    const coverage: CoverageReport = {
      included_paths: ["src/app.ts", "config/.env", "certs/server.pem"],
      excluded_paths: [{ path: "keys/service-account.json", kind: "file", reason: "max_file_bytes" }],
      ignored_paths: [{ path: "node_modules", kind: "directory", reason: "ignored" }],
      caps: { max_files: 10, max_depth: 5, max_file_bytes: 100 },
      truncation: { truncated: false, reasons: [], coverage_events_truncated: false },
      files_reviewed: ["src/app.ts", ".env.local"],
      candidate_dispositions: [
        {
          id: "SEC-001",
          disposition: "needs_review",
          reason: "confirm config/.env.production:3",
          file: "config/.env.production:3",
        },
      ],
      candidate_disposition_counts: {
        reportable: 0,
        needs_review: 1,
        suppressed: 0,
        not_applicable: 0,
        deferred: 0,
      },
      scan_status: "complete",
      not_observed_means: "no_candidate_in_files_reviewed",
    };
    const safe = redactCoverageReport(coverage);
    assert.deepEqual(safe.included_paths, [
      "src/app.ts",
      "config/[redacted-secret-file]",
      "certs/[redacted-secret-file]",
    ]);
    assert.equal(safe.excluded_paths[0]?.path, "keys/[redacted-secret-file]");
    assert.equal(safe.ignored_paths[0]?.path, "node_modules");
    assert.deepEqual(safe.files_reviewed, ["src/app.ts", "[redacted-secret-file]"]);
    assert.equal(safe.candidate_dispositions[0]?.file, "config/[redacted-secret-file]:3");
    assert.ok(!safe.candidate_dispositions[0]?.reason.includes(".env.production"));
  });
});
