import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { toolError, toolSuccess } from "./envelope.js";
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
import { escapeMarkdown, markdownCode, renderMarkdownDocument } from "./markdown.js";

describe("secret evidence redaction", () => {
  it("redacts secret shapes before Markdown escaping can transform them", () => {
    const githubToken = `ghp_${"A".repeat(32)}`;
    const assignmentSecret = "markdown-secret-value-123";
    const markdown = renderMarkdownDocument({
      title: `Review ${githubToken}`,
      summary: `token=${assignmentSecret}`,
      metadata: [{ label: "Project", value: `/repo/${githubToken}` }],
      sections: [
        {
          heading: `Section ${githubToken}`,
          paragraphs: [`password=${assignmentSecret}`],
          fields: [{ label: "Evidence", value: githubToken, valueCode: true }],
          bullets: [githubToken],
        },
      ],
    });
    const normalizedMarkdown = markdown.replaceAll("\\", "");

    assert.ok(!normalizedMarkdown.includes(githubToken));
    assert.ok(!normalizedMarkdown.includes(assignmentSecret));
    assert.ok(!markdownCode(githubToken).replaceAll("\\", "").includes(githubToken));
    assert.match(markdown, /REDACTED/);
  });

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

  it("preserves boundary punctuation around redacted secret names", () => {
    assert.equal(
      redactedEvidence("(see credentials.json)"),
      "(see [redacted-secret-file])",
    );
    assert.equal(
      redactedEvidence("rotate credentials.json."),
      "rotate [redacted-secret-file].",
    );
    assert.equal(
      redactedEvidence("rotate server.pem."),
      "rotate [redacted-secret-file].",
    );
    assert.equal(redactedEvidence("server.pem."), "[redacted-secret-file].");
    assert.equal(
      redactedEvidence("credentials.json, then rotate"),
      "[redacted-secret-file], then rotate",
    );
  });

  it("redacts bare secret basenames used as whole-string paths", () => {
    assert.equal(redactedEvidence(".env"), "[redacted-secret-file]");
    assert.equal(redactedEvidence("id_rsa"), "[redacted-secret-file]");
    assert.equal(redactedEvidence("credentials"), "[redacted-secret-file]");
    assert.equal(
      redactFinding({
        id: "SEC-ROOT",
        title: "Root env",
        description: "root-level secret file",
        severity: "high",
        confidence: "high",
        category: "secrets",
        file: ".env",
        line: 1,
        evidence: "TOKEN=x",
        impact_if_unremediated: "i",
        remediation: "r",
        residual_risk: "r",
        verification_suggestion: "v",
      }).file,
      "[redacted-secret-file]",
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

  it("preserves quotes and structure for labeled quoted values (no double-apply)", () => {
    // Overlapping quoted+unquoted portion edits previously dropped closing
    // quotes, garbled short markers, and truncated JSON after the first secret.
    assert.equal(
      redactedEvidence('password="super-secret-value-123456"'),
      'password="[REDACTED:****]"',
    );
    assert.equal(
      redactedEvidence("password='super-secret-value-123456'"),
      "password='[REDACTED:****]'",
    );
    assert.equal(
      redactedEvidence("password=`super-secret-value-123456`"),
      "password=`[REDACTED:****]`",
    );
    assert.equal(redactedEvidence('password="short"'), 'password="[REDACTED:****]"');
    assert.equal(
      redactedEvidence('{"password": "my secret value 123", "api_key": "another value here"}'),
      '{"password": "[REDACTED:****]", "api_key": "[REDACTED:****]"}',
    );
    assert.equal(
      redactedEvidence('password="one-secret" token="two-secret"'),
      'password="[REDACTED:****]" token="[REDACTED:****]"',
    );
    assert.equal(
      redactedEvidence('password="secret-val" config/.env'),
      'password="[REDACTED:****]" config/[redacted-secret-file]',
    );
  });

  it("redacts single-quoted and template-quoted labeled values", () => {
    const safe = redactedEvidence(
      "config = { 'client_secret': 'abc def ghi', `token`: `tpl value 789` }",
    );
    assert.ok(!safe.includes("abc def ghi"));
    assert.ok(!safe.includes("tpl value 789"));
    assert.ok(safe.includes("client_secret"));
    assert.equal(
      safe,
      "config = { 'client_secret': '[REDACTED:****]', `token`: `[REDACTED:****]` }",
    );
  });

  it("redacts quoted values over 2048 chars including multi-word passphrases", () => {
    // The quoted rule bounds its value group; the unquoted fallback stops at
    // the first space, so an over-long multi-word value must not leak its tail.
    const long = `${"a".repeat(2500)} ${"b".repeat(60)}`;
    assert.ok(long.length > 2048);
    const raw = `password="${long}"`;
    const safe = redactedEvidence(raw);
    assert.ok(!safe.includes(long));
    assert.ok(!safe.includes("b".repeat(60)));
    assert.ok(!safe.includes("a".repeat(2500)));
    assert.equal(safe, `password="[REDACTED:****]"`);
  });

  it("redacts YAML block scalars", () => {
    const safe = redactedEvidence(
      "api:\n  secret: |\n    first-line-value\n    second-line-value\n  other: 1",
    );
    assert.ok(!safe.includes("first-line-value"));
    assert.ok(!safe.includes("second-line-value"));
    // Keep the block indicator; body is a single marker (no double-mark of `|`).
    assert.equal(
      safe,
      "api:\n  secret: |\n[REDACTED:****]\n  other: 1",
    );
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

describe("escaped-markdown secret redaction", () => {
  // One-layer unescape of the same punctuation set escapeMarkdown escapes,
  // proving a consumer cannot recover a secret by undoing the escaping.
  const unescapeOneLayer = (value: string): string =>
    value.replace(/\\([\\`*_{}[\]()#+.!|<>~=\-:\/@&$%^?'",;])/g, "$1");
  // Seams that escape punctuation themselves (escapeMarkdown) add a second
  // layer on top of pre-escaped input; strip all layers the consumer would.
  const fullyUnescaped = (value: string): string => {
    let current = value;
    for (let i = 0; i < 8; i++) {
      const next = unescapeOneLayer(current);
      if (next === current) return current;
      current = next;
    }
    return current;
  };
  // Pre-escape content exactly like a Markdown renderer already did.
  const preEscaped = (value: string): string =>
    value.replace(/([\\`*_{}[\]()#+.!|<>~=\-:\/@&$%^?'",;])/g, "\\$1");

  const githubToken = `ghp_${"A".repeat(32)}`;
  const assignmentSecret = "markdown-secret-value-123";
  const bearerValue = "abcdefghijklmnop";
  const uriPassword = "dbpass123";
  const pemBody = [
    "-----BEGIN RSA PRIVATE KEY-----",
    "SECRETKEYMATERIALHERE1234567890",
    "MORESECRETBASE64LINES",
    "-----END RSA PRIVATE KEY-----",
  ].join("\n");

  it("redacts pre-escaped token shapes and assignments through escapeMarkdown", () => {
    const escaped = escapeMarkdown(preEscaped(`token=${assignmentSecret} ${githubToken}`));
    assert.ok(!escaped.includes(assignmentSecret));
    assert.ok(!escaped.includes(githubToken));
    assert.ok(!fullyUnescaped(escaped).includes(assignmentSecret));
    assert.ok(!fullyUnescaped(escaped).includes(githubToken));
    assert.match(escaped, /REDACTED/);
  });

  it("redacts pre-escaped authorization and URI credentials through markdownCode", () => {
    const code = markdownCode(
      preEscaped(`Authorization: Bearer ${bearerValue} postgres://app:${uriPassword}@db.internal/x`),
    );
    assert.ok(!code.includes(bearerValue));
    assert.ok(!code.includes(uriPassword));
    assert.ok(!unescapeOneLayer(code).includes(bearerValue));
    assert.ok(!unescapeOneLayer(code).includes(uriPassword));
  });

  it("redacts pre-escaped key material through markdown rendering", () => {
    const doc = renderMarkdownDocument({
      title: "Key review",
      summary: preEscaped(pemBody),
    });
    assert.ok(!doc.includes("SECRETKEYMATERIALHERE1234567890"));
    assert.ok(!unescapeOneLayer(doc).includes("SECRETKEYMATERIALHERE1234567890"));
    assert.match(doc, /REDACTED/);
  });

  it("redacts pre-escaped secret paths in evidence", () => {
    const cases: Array<[string, string]> = [
      [preEscaped("config/.env.production:3"), ".env.production"],
      [preEscaped("keys/service-account.json"), "service-account.json"],
      [preEscaped("certs/server.pem"), "server.pem"],
      [preEscaped("rotate credentials.json."), "credentials.json"],
    ];
    for (const [raw, secretPart] of cases) {
      const safe = redactedEvidence(raw);
      assert.match(safe, /\[redacted-secret-file\]/);
      assert.ok(!unescapeOneLayer(safe).includes(secretPart), `${secretPart} recoverable`);
    }
  });

  it("redacts pre-escaped secrets at the toolSuccess envelope seam", () => {
    const success = toolSuccess({
      ok: true as const,
      project_root: "/repo",
      summary: preEscaped(`token=${assignmentSecret}`),
      nested: { metadata: { api_key: preEscaped(uriPassword) } },
    });
    const data = success.structuredContent as {
      summary: string;
      nested: { metadata: { api_key: string } };
    };
    assert.ok(!data.summary.includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(data.summary).includes(assignmentSecret));
    assert.ok(!data.nested.metadata.api_key.includes(uriPassword));
    assert.ok(!unescapeOneLayer(data.nested.metadata.api_key).includes(uriPassword));
    assert.ok(!unescapeOneLayer(success.content[0]?.text ?? "").includes(assignmentSecret));
  });

  it("redacts pre-escaped secrets at the toolError envelope seam", () => {
    const error = toolError(new Error(preEscaped(`token=${assignmentSecret}`)), "x");
    const text = error.content[0]?.text ?? "";
    const message = error.structuredContent.error;
    assert.ok(!message.includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(message).includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(text).includes(assignmentSecret));
  });

  it("redacts pre-escaped secrets inside nested finding structures", () => {
    const safe = redactValue({
      ok: true,
      findings: [{ evidence: preEscaped(`password=${assignmentSecret}`) }],
      config: { token: preEscaped(githubToken) },
    }) as {
      findings: [{ evidence: string }];
      config: { token: string };
    };
    assert.ok(!safe.findings[0].evidence.includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(safe.findings[0].evidence).includes(assignmentSecret));
    assert.ok(!safe.config.token.includes(githubToken));
    assert.ok(!unescapeOneLayer(safe.config.token).includes(githubToken));
  });

  it("keeps non-secret escaped prose untouched", () => {
    const prose = "see \\*docs\\* and `code` — no secrets";
    assert.equal(redactedEvidence(prose), prose);
    assert.equal(unescapeOneLayer(redactedEvidence(prose)), unescapeOneLayer(prose));
  });

  it("preserves non-secret escapes across multiple redactions", () => {
    // Multi-span edits must not de-escape later punctuation when a token
    // redaction sits between assignments (greedy string resync previously
    // rewrote subsequent `\\=` / `\\_` after the first marker).
    const twoAssigns = preEscaped(`token=${assignmentSecret} password=${assignmentSecret}`);
    const twoSafe = redactedEvidence(twoAssigns);
    assert.equal(
      twoSafe,
      `token\\=[REDACTED:****] password\\=[REDACTED:****]`,
    );
    assert.ok(!unescapeOneLayer(twoSafe).includes(assignmentSecret));

    const withToken = preEscaped(
      `token=${assignmentSecret} ${githubToken} password=${assignmentSecret}`,
    );
    const withTokenSafe = redactedEvidence(withToken);
    assert.equal(
      withTokenSafe,
      `token\\=[REDACTED:****] [REDACTED:****] password\\=[REDACTED:****]`,
    );
    assert.ok(!unescapeOneLayer(withTokenSafe).includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(withTokenSafe).includes(githubToken));

    const prose = preEscaped(`see *docs* token=${assignmentSecret} and _more_`);
    const proseSafe = redactedEvidence(prose);
    assert.equal(
      proseSafe,
      `see \\*docs\\* token\\=[REDACTED:****] and \\_more\\_`,
    );
    assert.ok(!unescapeOneLayer(proseSafe).includes(assignmentSecret));

    const pathAndToken = preEscaped(`config/.env token=${assignmentSecret}`);
    const pathSafe = redactedEvidence(pathAndToken);
    assert.equal(pathSafe, `config\\/[redacted-secret-file] token\\=[REDACTED:****]`);
    assert.ok(!unescapeOneLayer(pathSafe).includes(assignmentSecret));
    assert.ok(!unescapeOneLayer(pathSafe).includes(".env"));
  });

  it("preserves pre-escaped quoted assignments without double-apply garble", () => {
    const quoted = preEscaped(`password="${assignmentSecret}"`);
    assert.equal(redactedEvidence(quoted), `password\\=\\"[REDACTED:****]\\"`);
    const multi = preEscaped(`password="${assignmentSecret}" token="${assignmentSecret}"`);
    assert.equal(
      redactedEvidence(multi),
      `password\\=\\"[REDACTED:****]\\" token\\=\\"[REDACTED:****]\\"`,
    );
  });

  it("masks one-layer pre-escaped secrets but not double-escaped input", () => {
    // One layer is the contract: content already escaped once (Markdown) is
    // masked. Double-escaped material is out of scope — escapeMarkdown redacts
    // before it adds its own layer, so the normal render path stays safe.
    const oneLayer = preEscaped(`token=${assignmentSecret}`);
    assert.equal(redactedEvidence(oneLayer), `token\\=[REDACTED:****]`);
    const doubleLayer = preEscaped(oneLayer);
    const doubleSafe = redactedEvidence(doubleLayer);
    assert.ok(
      fullyUnescaped(doubleSafe).includes(assignmentSecret),
      "double-escaped secrets remain out of one-layer policy scope",
    );
  });
});

describe("secret-shaped object key redaction", () => {
  it("redacts secret-shaped keys while preserving values and ordinary keys", () => {
    const safe = redactValue({
      ok: true,
      by_extension: { ".env": 2, ".ts": 5, ".pem": 1, ".key": 1 },
    }) as { ok: boolean; by_extension: Record<string, number> };
    const encoded = JSON.stringify(safe);
    assert.ok(!encoded.includes('".env"'));
    assert.ok(!encoded.includes('".pem"'));
    assert.ok(!encoded.includes('".key"'));
    assert.match(encoded, /\[redacted-secret-file\]/);
    assert.equal(safe.by_extension[".ts"], 5);
    assert.equal(safe.ok, true);
    // Bare credential extensions collide onto the same marker family.
    assert.equal(safe.by_extension["[redacted-secret-file]"], 2);
    assert.equal(safe.by_extension["[redacted-secret-file]#2"], 1);
    assert.equal(safe.by_extension["[redacted-secret-file]#3"], 1);
  });

  it("keeps field-name-based value redaction while sanitizing keys", () => {
    const safe = redactValue({
      credentials: { token: "secret-value-1" },
      by_extension: { ".env": 1 },
    }) as { "[redacted-secret-file]": unknown; by_extension: Record<string, number> };
    // The `credentials` field key is itself secret-shaped: redacted, and its
    // value redacted wholesale by field name.
    assert.equal(safe["[redacted-secret-file]"], "[REDACTED:****]");
    assert.equal(safe.by_extension["[redacted-secret-file]"], 1);
    assert.ok(!JSON.stringify(safe).includes('"credentials"'));
    assert.ok(!JSON.stringify(safe).includes('".env"'));
  });

  it("handles redacted-key collisions deterministically", () => {
    const safe = redactValue({
      by_extension: { ".env": 2, ".ts": 1 },
      file_counts: { ".env": 3, id_rsa: 4, credentials: 5, ".ts": 6 },
    }) as {
      by_extension: Record<string, number>;
      file_counts: Record<string, number>;
    };
    assert.deepEqual(Object.keys(safe.by_extension), ["[redacted-secret-file]", ".ts"]);
    assert.deepEqual(Object.keys(safe.file_counts), [
      "[redacted-secret-file]",
      "[redacted-secret-file]#2",
      "[redacted-secret-file]#3",
      ".ts",
    ]);
    assert.equal(safe.by_extension["[redacted-secret-file]"], 2);
    assert.equal(safe.by_extension[".ts"], 1);
    assert.equal(safe.file_counts["[redacted-secret-file]"], 3);
    assert.equal(safe.file_counts["[redacted-secret-file]#2"], 4);
    // `credentials` is a secret field name: the colliding key is sanitized and
    // its value is redacted wholesale by the field-name policy.
    assert.equal(safe.file_counts["[redacted-secret-file]#3"], "[REDACTED:****]");
    assert.equal(safe.file_counts[".ts"], 6);
  });

  it("redacts secret-shaped keys in envelope structuredContent", () => {
    const success = toolSuccess({
      ok: true as const,
      project_root: "/repo",
      summary: "inventory",
      by_extension: { ".env": 2, ".ts": 3 },
    });
    const data = success.structuredContent as { by_extension: Record<string, number> };
    const encoded = JSON.stringify(data);
    assert.ok(!encoded.includes('".env"'));
    assert.ok(encoded.includes("[redacted-secret-file]"));
    assert.ok(encoded.includes('".ts"'));
    assert.equal(data.by_extension["[redacted-secret-file]"], 2);
    assert.equal(data.by_extension[".ts"], 3);
  });

  it("redacts a synthetic secret-shaped filename extension in an in-memory inventory", () => {
    // Mirrors list_project_structure histogram keys: walkProject normalizes
    // `.env.production` / `.env.local` files to the `.env` extension, so a
    // repository containing env files yields a secret-shaped histogram key.
    const payload = {
      ok: true as const,
      project_root: "/repo",
      summary: "inventory",
      file_count: 3,
      by_extension: { ".env": 1, ".ts": 2 } as Record<string, number>,
      sample_files: [] as string[],
    };
    const result = toolSuccess(payload);
    const data = result.structuredContent as { by_extension: Record<string, number> };
    const encoded = JSON.stringify(data);
    assert.ok(!encoded.includes('".env"'));
    assert.ok(encoded.includes("[redacted-secret-file]"));
    assert.deepEqual(Object.keys(data.by_extension), ["[redacted-secret-file]", ".ts"]);
    assert.equal(data.by_extension[".ts"], 2);
    assert.equal(data.by_extension["[redacted-secret-file]"], 1);
  });
});
