import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  redactCoverageReport,
  redactFinding,
  redactValue,
  redactedEvidence,
  redactedSecretPath,
  redactedSecretPaths,
} from "./redact.js";
import type { CoverageReport, Finding } from "./types.js";
import { snippetAround } from "./filesystem.js";

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

  it("keeps ordinary prose mentioning secret-like words readable", () => {
    assert.equal(redactedEvidence("No hardcoded credentials"), "No hardcoded credentials");
    assert.equal(
      redactedEvidence(
        "Never use discovered credentials against systems — only help owners fix and rotate.",
      ),
      "Never use discovered credentials against systems — only help owners fix and rotate.",
    );
    assert.equal(
      redactedEvidence('title "No hardcoded credentials" in a checklist'),
      'title "No hardcoded credentials" in a checklist',
    );
    assert.equal(
      redactedEvidence("check the .env file for the value"),
      "check the .env file for the value",
    );
  });

  it("redacts secret-like names in path context only", () => {
    assert.equal(
      redactedEvidence("config/credentials.json"),
      "config/[redacted-secret-file]",
    );
    assert.equal(redactedEvidence("src/.env"), "src/[redacted-secret-file]");
    assert.equal(redactedEvidence("src/.env:12"), "src/[redacted-secret-file]:12");
    assert.equal(
      redactedEvidence("keys/service-account.json:12:4"),
      "keys/[redacted-secret-file]:12:4",
    );
    assert.equal(
      redactedEvidence("credentials.json alone in prose"),
      "[redacted-secret-file] alone in prose",
    );
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

describe("structural and URI secret redaction", () => {
  it("redacts quoted JSON keys with space-containing values", () => {
    const safe = redactedEvidence(
      '{"password": "my secret value 123", "api_key": "another value here", "nested": {"client_secret": "deep value 456"}}',
    );
    assert.ok(!safe.includes("my secret value 123"));
    assert.ok(!safe.includes("another value here"));
    assert.ok(!safe.includes("deep value 456"));
  });

  it("redacts single-quoted and template-quoted labeled values", () => {
    const safe = redactedEvidence(
      "config = { 'client_secret': 'abc def ghi', `token`: `tpl value 789` }",
    );
    assert.ok(!safe.includes("abc def ghi"));
    assert.ok(!safe.includes("tpl value 789"));
    assert.ok(safe.includes("client_secret"));
  });

  it("redacts YAML block scalars", () => {
    const safe = redactedEvidence(
      "api:\n  secret: |\n    first-line-value\n    second-line-value\n  other: 1",
    );
    assert.ok(!safe.includes("first-line-value"));
    assert.ok(!safe.includes("second-line-value"));
  });

  it("redacts URI userinfo credentials and keeps the host", () => {
    const safe = redactedEvidence(
      "postgres://app:dbpass123@db.internal:5432/main https://user:webpass456@example.com/x",
    );
    assert.ok(!safe.includes("dbpass123"));
    assert.ok(!safe.includes("webpass456"));
    assert.match(safe, /postgres:\/\/\[REDACTED:\*\*\*\*\]@db\.internal/);
    assert.match(safe, /https:\/\/\[REDACTED:\*\*\*\*\]@example\.com/);
  });

  it("redacts redis-style empty-user userinfo", () => {
    const safe = redactedEvidence("redis://:redispass789@cache:6379/0");
    assert.ok(!safe.includes("redispass789"));
    assert.match(safe, /redis:\/\/\[REDACTED:\*\*\*\*\]@cache/);
  });

  it("redacts query-string credentials inside URLs", () => {
    const safe = redactedEvidence(
      "https://api.example.com/v1?token=querysecret&api_key=keyvalue123&x=1",
    );
    assert.ok(!safe.includes("querysecret"));
    assert.ok(!safe.includes("keyvalue123"));
    assert.ok(safe.includes("x=1"));
  });

  it("redacts compound and prefixed keys without over-redacting prose", () => {
    const safe = redactedEvidence(
      "api_token=compound1 access_token=compound2 dbpassword=prose-key db_password=prose-key2",
    );
    assert.ok(!safe.includes("compound1"));
    assert.ok(!safe.includes("compound2"));
    assert.ok(!safe.includes("prose-key"));
    assert.ok(!safe.includes("prose-key2"));
  });

  it("does not redact harmless email-like text or mailto links", () => {
    const safe = redactedEvidence(
      "contact security@example.com or admin@corp.example; mailto:ops@example.com",
    );
    assert.ok(safe.includes("security@example.com"));
    assert.ok(safe.includes("admin@corp.example"));
    assert.ok(safe.includes("ops@example.com"));
  });

  it("recursively redacts nested metadata objects", () => {
    const value = redactValue({
      ok: true,
      count: 3,
      nested: { auth: { token: "nestedsecret456" } },
      list: ["api_key=arrsecret789", 5],
      safe: "src/app.ts",
    });
    const encoded = JSON.stringify(value);
    assert.ok(!encoded.includes("nestedsecret456"));
    assert.ok(!encoded.includes("arrsecret789"));
    assert.equal((value as { count: number }).count, 3);
    assert.ok(encoded.includes("src/app.ts"));
  });

  it("preserves dynamic identifier keys while redacting secret fields", () => {
    const value = redactValue({
      items_per_pack: { secrets: 2, token: 1 },
      secret: "do-not-return",
    }) as { items_per_pack: Record<string, unknown>; secret: string };
    assert.deepEqual(value.items_per_pack, { secrets: 2, token: 1 });
    assert.equal(value.secret, "[REDACTED:****]");
  });

  it("redacts every finding metadata field, not only narrative strings", () => {
    const finding: Finding = {
      id: "SEC-002",
      title: "Metadata leak test",
      description: "Checks category, cwe, owasp and tags redaction.",
      severity: "high",
      confidence: "medium",
      category: 'auth api_key="catleak123"',
      cwe: "CWE-200 token=owaspleak456",
      owasp: "A01 token=owaspsecret789",
      stack: "typescript",
      file: "src/config.ts",
      line: 4,
      evidence: "evidence with token=evsecret000",
      impact_if_unremediated: "Impact.",
      remediation: "Remediate.",
      residual_risk: "Residual.",
      verification_suggestion: "Verify.",
      disposition: "needs_review",
      disposition_reason: 'password = "reasonleak111"',
      tags: ["api_token=tagleak222", "safe-tag"],
      counterevidence: ["no token=countersecret333"],
    };
    const safe = redactFinding(finding);
    assert.ok(!safe.category.includes("catleak123"));
    assert.ok(!safe.cwe?.includes("owaspleak456"));
    assert.ok(!safe.owasp?.includes("owaspsecret789"));
    assert.ok(!safe.disposition_reason?.includes("reasonleak111"));
    assert.ok(!safe.tags?.some((tag) => tag.includes("tagleak222")));
    assert.ok(!safe.counterevidence?.some((item) => item.includes("countersecret333")));
    assert.ok(safe.tags?.some((tag) => tag === "safe-tag"));
    assert.equal(safe.file, "src/config.ts");
    assert.equal(safe.line, 4);
    assert.equal(safe.id, "SEC-002");
  });

  it("redacts source context when snippets are constructed", () => {
    const snippet = snippetAround(
      'const config = { "api_key": "snippet-secret-123" }; postgres://app:dbpass123@db.local',
      20,
      200,
    );
    assert.ok(!snippet.includes("snippet-secret-123"));
    assert.ok(!snippet.includes("dbpass123"));
  });
});
