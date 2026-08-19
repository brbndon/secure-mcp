import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
import {
  appliedSecretsPackIds,
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

describe("appliedSecretsPackIds", () => {
  it("maps evaluated families without claiming consulted-only packs", () => {
    assert.deepEqual(appliedSecretsPackIds(["secrets.secret-patterns"]), ["secrets"]);
    assert.deepEqual(
      appliedSecretsPackIds(["secrets.secret-patterns", "web-next.client-bundle-secrets"]),
      ["secrets", "web-next"],
    );
    assert.deepEqual(appliedSecretsPackIds(["core.secrets"]), []);
  });
});

describe("secrets stack routing", () => {
  it("does not run or claim Next.js detectors for explicit expo or common focus", () => {
    assert.equal(shouldRunNextjsSecretDetectors("expo"), false);
    assert.equal(shouldRunNextjsSecretDetectors("common"), false);
    assert.equal(shouldRunNextjsSecretDetectors("swift"), false);
    assert.equal(shouldRunNextjsSecretDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsSecretDetectors("typescript"), false);
    assert.equal(shouldRunNextjsSecretDetectors("auto"), false);

    assert.deepEqual(secretsPackIdsForStack("expo"), ["core", "secrets"]);
    assert.deepEqual(secretsPackIdsForStack("common"), ["core", "secrets"]);
    assert.ok(!secretsPackIdsForStack("expo").includes("web-next"));
    assert.ok(secretsPackIdsForStack("nextjs").includes("web-next"));
    assert.ok(!secretsPackIdsForStack("typescript").includes("web-next"));
  });

  it("runs Swift secret detectors only for auto or swift focus", () => {
    assert.equal(shouldRunSwiftSecretDetectors("swift"), true);
    assert.equal(shouldRunSwiftSecretDetectors("auto"), false);
    assert.equal(shouldRunSwiftSecretDetectors("expo"), false);
    assert.equal(shouldRunSwiftSecretDetectors("nextjs"), false);
    assert.ok(secretsPackIdsForStack("swift").includes("swift-ios"));
    assert.ok(!secretsPackIdsForStack("expo").includes("swift-ios"));
  });

  it("derives auto detector families and pack claims from the detected Expo stack", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-secrets-expo-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 20,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { expo: "53.0.0", react: "19.0.0" } }),
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "app.json"),
        JSON.stringify({ expo: { name: "x" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "App.tsx"), "export default function App() {}\n", "utf8");

      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_review_secrets",
        arguments: { project_root: root, stack: "auto", response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        applied_pack_ids: string[];
        knowledge_pack_traceability: {
          consulted_pack_ids: string[];
          detector_families_run: string[];
          detector_families_not_run: string[];
        };
      };

      assert.deepEqual(data.knowledge_pack_traceability.consulted_pack_ids, ["core", "secrets"]);
      assert.deepEqual(data.applied_pack_ids, ["secrets"]);
      assert.ok(!data.applied_pack_ids.includes("core"));
      assert.ok(!data.applied_pack_ids.includes("web-next"));
      assert.ok(!data.applied_pack_ids.includes("swift-ios"));
      const detectorTrace = JSON.stringify(data.knowledge_pack_traceability);
      assert.ok(!detectorTrace.includes("web-next.client-bundle-secrets"));
      assert.ok(!detectorTrace.includes("swift-ios.secret-handling"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("planted tiny-app secret is recalled and redacted", () => {
  it("surfaces secrets.secret-patterns without the raw planted token", async () => {
    const fixtureRoot = path.resolve(fileURLToPath(new URL("../../fixtures/tiny-app", import.meta.url)));
    const planted = "planted_secure_mcp_eval_api_key_value_123456";
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 80,
      maxFileBytes: 16_384,
      maxDepth: 12,
      allowedRoots: [fixtureRoot],
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_review_secrets",
        arguments: { project_root: fixtureRoot, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        findings: Array<{ rule_family?: string; evidence?: string; severity?: string }>;
      };
      const secrets = data.findings.filter((finding) => finding.rule_family === "secrets.secret-patterns");
      assert.ok(secrets.length > 0, "planted secret must surface as secrets.secret-patterns");
      assert.ok(secrets.some((finding) => finding.severity === "high" || finding.severity === "critical"));
      const serialized = JSON.stringify(result.structuredContent);
      assert.ok(!serialized.includes(planted), "raw planted token leaked in structured content");
      for (const finding of secrets) {
        assert.match(finding.evidence ?? "", /REDACTED|\*{4}/);
      }
    } finally {
      await client.close();
      await server.close();
    }
  });
});
