import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { createServer } from "../server.js";
import type { Finding } from "../lib/types.js";

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: "INJ-001",
    title: "Unsafe sink",
    description: "Candidate sink observed.",
    severity: "high",
    confidence: "medium",
    category: "injection-risk",
    evidence: "db.query(input)",
    impact_if_unremediated: "Integrity risk.",
    remediation: "Parameterize queries.",
    residual_risk: "Other sinks may remain.",
    verification_suggestion: "Add regression tests.",
    ...overrides,
  };
}

async function callProduceResult(
  findings: Finding | Finding[],
  reportTitle = "Boundary report",
  response_format: "json" | "markdown" = "markdown",
): Promise<{ text: string; structured: any }> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer({
    name: "secure-mcp-test",
    version: "test",
    defaultMaxFiles: 20,
    maxFileBytes: 1024,
    maxDepth: 12,
  });
  const client = new Client({ name: "secure-mcp-test-client", version: "test" });

  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({
      name: "secure_mcp_produce_findings",
      arguments: {
        findings: Array.isArray(findings) ? findings : [findings],
        project_root: "/tmp/reviewed-project",
        report_title: reportTitle,
        response_format,
      },
    });
    assert.equal(result.isError, undefined);
    const textBlock = result.content.find((block) => block.type === "text");
    assert.ok(textBlock);
    assert.equal(textBlock.type, "text");
    return { text: textBlock.text, structured: result.structuredContent };
  } finally {
    await client.close();
    await server.close();
  }
}

async function callProduceFindings(finding: Finding, reportTitle = "Boundary report"): Promise<string> {
  return (await callProduceResult(finding, reportTitle)).text;
}

/** Call the tool without asserting success — for schema-rejection tests. */
async function callProduceRaw(args: Record<string, unknown>): Promise<{
  isError: boolean | undefined;
  text: string;
  structured: any;
}> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer({
    name: "secure-mcp-test",
    version: "test",
    defaultMaxFiles: 20,
    maxFileBytes: 1024,
    maxDepth: 12,
  });
  const client = new Client({ name: "secure-mcp-test-client", version: "test" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({
      name: "secure_mcp_produce_findings",
      arguments: args,
    });
    const textBlock = result.content.find((block) => block.type === "text");
    return {
      isError: result.isError,
      text: textBlock && textBlock.type === "text" ? textBlock.text : "",
      structured: result.structuredContent,
    };
  } finally {
    await client.close();
    await server.close();
  }
}

describe("produceFindings markdown proof fields", () => {
  it("does not let caller-supplied instance ids merge unrelated findings", async () => {
    const result = await callProduceResult(
      [
        makeFinding({ id: "A", file: "src/a.ts", line: 10, instance_id: "same-id" }),
        makeFinding({ id: "B", file: "src/b.ts", line: 10, instance_id: "same-id" }),
      ],
      "Identity report",
      "json",
    );
    const findings = result.structured.findings as Finding[];
    assert.equal(findings.length, 2);
    assert.notEqual(findings[0]?.instance_id, "same-id");
    assert.notEqual(findings[1]?.instance_id, "same-id");
    assert.notEqual(findings[0]?.instance_id, findings[1]?.instance_id);
  });

  it("returns traceability and proof fields through the MCP Markdown boundary", async () => {
    const finding = makeFinding({
      title: "Unsafe sink",
      description: "Candidate sink observed.",
      file: "src/route.ts",
      line: 12,
      evidence: "db.query(input)",
      source: "Request query string",
      control: "Use parameterized API",
      sink: "src/route.ts:12",
      disposition: "needs_review",
      disposition_reason: "Heuristic only",
      counterevidence: ["No runtime proof"],
      proof_gap: ["Trace data flow"],
      validation: ["Code review the sink"],
    });

    const md = await callProduceFindings(finding);
    assert.match(md, /Proof gap/i);
    assert.match(md, /Source:/);
    assert.match(md, /Control:/);
    assert.match(md, /Sink:/);
    assert.match(md, /Counterevidence/i);
    assert.match(md, /Validation/i);
    assert.match(md, /Disposition reason/i);
  });

  it("escapes hostile GFM constructs in the Markdown returned through MCP", async () => {
    const hostileText = [
      "https://attacker.example/path?q=1&x=2",
      "www.attacker.example/path",
      "mailto:security@example.com",
      "//cdn.example/image.png",
      "![image](https://cdn.example/image.png)",
      "[reference][id]",
      "[nested [label]](https://example.com)",
      "<img src=x onerror=alert(1)>",
      "# heading",
      "> blockquote",
      "- list item",
      "| table | cell |\n| --- | --- |\n| value | value |",
      "*emphasis* **strong** ~~strikethrough~~",
      "`backticks`",
    ].join("\n");
    const finding = makeFinding({
      id: "INJ-002",
      title: hostileText,
      description: hostileText,
      evidence: "const value = `secret`;\n# not a heading",
      impact_if_unremediated: hostileText,
      remediation: hostileText,
      residual_risk: hostileText,
      verification_suggestion: hostileText,
      source: hostileText,
      control: hostileText,
      sink: hostileText,
      counterevidence: [hostileText],
      proof_gap: [hostileText],
      validation: [hostileText],
    });

    const md = await callProduceFindings(finding, "Hostile input report");

    for (const escaped of [
      String.raw`https\:\/\/attacker\.example\/path\?q\=1\&x\=2`,
      String.raw`www\.attacker\.example\/path`,
      String.raw`mailto\:security\@example\.com`,
      String.raw`\/\/cdn\.example\/image\.png`,
      String.raw`\!\[image\]\(https\:\/\/cdn\.example\/image\.png\)`,
      String.raw`\[reference\]\[id\]`,
      String.raw`\[nested \[label\]\]\(https\:\/\/example\.com\)`,
      String.raw`\<img src\=x onerror\=alert\(1\)\>`,
      String.raw`\# heading`,
      String.raw`\> blockquote`,
      String.raw`\- list item`,
      String.raw`\| table \| cell \|`,
      String.raw`\*emphasis\* \*\*strong\*\* \~\~strikethrough\~\~`,
      "\\`backticks\\`",
    ]) {
      assert.ok(md.includes(escaped), `missing escaped payload fragment: ${escaped}`);
    }

    assert.ok(!md.includes("[reference][id]"));
    assert.ok(!md.includes("![image](https://cdn.example/image.png)"));
    assert.ok(!md.includes("<img src=x onerror=alert(1)>"));
    assert.ok(!md.includes("\n# heading"));
    assert.ok(!md.includes("\n> blockquote"));
    assert.ok(!md.includes("\n- list item"));

    const evidenceMatch = md.match(/#### Evidence\n[^\n]*\n\n([^\n]*)/);
    assert.ok(evidenceMatch, "expected an inline evidence code span in returned Markdown");
    const evidenceLine = evidenceMatch[1];
    assert.equal((evidenceLine.match(/`/g) ?? []).length, 2);
    assert.ok(evidenceLine.includes("\\u0060"));
    assert.ok(evidenceLine.includes("\\n# not a heading"));
  });
});

describe("produceFindings bounded inputs and redaction", () => {
  it("rejects oversized finding strings at the MCP boundary", async () => {
    const result = await callProduceRaw({
      findings: [makeFinding({ title: "t".repeat(4_000) })],
    });
    assert.equal(result.isError, true);
    assert.match(result.text, /too_big|too small|Invalid|Expected|error/i);
  });

  it("rejects oversized nested arrays at the MCP boundary", async () => {
    const result = await callProduceRaw({
      findings: [
        makeFinding({ counterevidence: Array.from({ length: 21 }, (_, i) => `item-${i}`) }),
      ],
    });
    assert.equal(result.isError, true);
  });

  it("rejects a request that exceeds the total decoded size budget", async () => {
    // 300 findings × ~2 KB each exceed the 500 KB decoded budget while every
    // individual field stays within its own cap.
    const findings = Array.from({ length: 300 }, () =>
      makeFinding({ description: "d".repeat(2_000) }),
    );
    const result = await callProduceRaw({ findings });
    assert.equal(result.isError, true);
    assert.match(result.text, /decoded size budget/i);
  });

  it("rejects an oversized project_root", async () => {
    const result = await callProduceRaw({
      findings: [makeFinding()],
      project_root: `/p/${"x".repeat(5_000)}`,
    });
    assert.equal(result.isError, true);
  });

  it("redacts caller-supplied metadata from structuredContent and Markdown alike", async () => {
    const secret = "metasecretvalue999";
    const finding = makeFinding({
      category: `authentication api_key=${secret}`,
      cwe: `CWE-200 token=${secret}`,
      owasp: `A01 token=${secret}`,
      tags: [`api_token=${secret}`],
      source: `connection postgres://app:${secret}@db:5432/main`,
    });
    const result = await callProduceResult(finding, "Redaction boundary report", "markdown");
    const encoded = JSON.stringify(result.structured);
    assert.ok(!encoded.includes(secret), "structuredContent must not carry the secret");
    assert.ok(!result.text.includes(secret), "Markdown must not carry the secret");
    assert.match(result.text, /REDACTED/);
  });

  it("redacts report_title and project_root before output", async () => {
    const secret = "titleleakvalue444";
    const result = await callProduceRaw({
      findings: [makeFinding()],
      report_title: `Review token=${secret}`,
      project_root: `/repo/token=${secret}/sub`,
    });
    assert.equal(result.isError, undefined);
    assert.ok(!result.text.includes(secret));
    assert.ok(!JSON.stringify(result.structured).includes(secret));
  });
});
