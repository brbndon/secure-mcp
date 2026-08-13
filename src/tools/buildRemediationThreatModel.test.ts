import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client } from "@modelcontextprotocol/client";
import { InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
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

describe("threat-model inventory coverage", () => {
  it("never reports complete content coverage for inventory-only threat models", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-threat-model-"));
    try {
      await fs.mkdir(path.join(root, "lib"), { recursive: true });
      await fs.writeFile(path.join(root, "a.ts"), "export const a = 1;\n", "utf8");
      await fs.writeFile(path.join(root, "lib", "auth.ts"), "export const auth = 1;\n", "utf8");

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
          name: "secure_mcp_build_remediation_threat_model",
          arguments: { project_root: root },
        });
        assert.equal(result.isError, undefined);
        const structured = result.structuredContent as {
          findings?: unknown[];
          coverage?: {
            scan_status: string;
            not_observed_means: string;
            review_basis?: string;
            files_reviewed: unknown[];
            candidate_disposition_counts: Record<string, number>;
          };
        };
        const coverage = structured.coverage;
        assert.ok(coverage, "threat model must return coverage");
        // Inventory-only tool: coverage must never claim complete content review
        // (the response may additionally be response-size-truncated, which is
        // reported honestly as truncated rather than complete).
        assert.notEqual(coverage.scan_status, "complete");
        assert.equal(coverage.review_basis, "inventory_only");
        assert.deepEqual(coverage.files_reviewed, []);
        assert.notEqual(coverage.not_observed_means, "no_candidate_in_files_reviewed");
        assert.ok(coverage.candidate_disposition_counts.needs_review > 0);
        assert.equal(coverage.candidate_disposition_counts.needs_review, 3);
        assert.ok(
          coverage.candidate_disposition_counts.needs_review >=
            (structured.findings?.length ?? 0),
        );
      } finally {
        await client.close();
        await server.close();
      }
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});
