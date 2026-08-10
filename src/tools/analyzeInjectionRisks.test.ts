/**
 * Routing matrix for secure_mcp_analyze_injection_risks:
 * stack focus → detector families, explicit per-family file applicability,
 * and pack ids derived from detectors that actually evaluated content.
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
import {
  appliedInjectionPackIds,
  injectionDetectorFamiliesForStack,
  injectionPackIdsForStack,
  injectionPatternAppliesToFile,
  shouldRunNextjsInjectionDetectors,
  shouldRunSwiftInjectionDetectors,
} from "./analyzeInjectionRisks.js";
import type { StackFocus } from "../lib/types.js";

const SWIFT_FAMILIES = [
  "swift-ios.injection",
  "swift-ios.configuration",
  "swift-ios.cryptography",
];

describe("injection detector family routing", () => {
  it("configures only detected families in auto mode", () => {
    assert.deepEqual(injectionDetectorFamiliesForStack("auto", ["common", "swift"]), [
      "core.injection",
      ...SWIFT_FAMILIES,
    ]);
    assert.deepEqual(
      injectionDetectorFamiliesForStack("auto", ["common", "typescript", "nextjs"]),
      ["core.injection", "web-next.injection"],
    );
    assert.deepEqual(injectionDetectorFamiliesForStack("auto", ["common"]), [
      "core.injection",
    ]);
    assert.deepEqual(
      injectionDetectorFamiliesForStack("auto", ["common", "typescript", "expo"]),
      ["core.injection"],
    );
    assert.deepEqual(injectionDetectorFamiliesForStack("auto", []), ["core.injection"]);
  });

  it("routes every accepted forced stack through explicit families", () => {
    assert.deepEqual(injectionDetectorFamiliesForStack("common"), ["core.injection"]);
    assert.deepEqual(injectionDetectorFamiliesForStack("typescript"), ["core.injection"]);
    assert.deepEqual(injectionDetectorFamiliesForStack("nextjs"), [
      "core.injection",
      "web-next.injection",
    ]);
    assert.deepEqual(injectionDetectorFamiliesForStack("expo"), ["core.injection"]);
    assert.deepEqual(injectionDetectorFamiliesForStack("swift"), SWIFT_FAMILIES);
  });

  it("excludes unrelated language inventories under forced stacks", () => {
    const mixed: StackFocus[] = ["common", "typescript", "nextjs", "expo", "swift"];
    assert.deepEqual(injectionDetectorFamiliesForStack("swift", mixed), SWIFT_FAMILIES);
    assert.deepEqual(injectionDetectorFamiliesForStack("typescript", mixed), [
      "core.injection",
    ]);
    assert.equal(shouldRunNextjsInjectionDetectors("swift", mixed), false);
    assert.equal(shouldRunSwiftInjectionDetectors("typescript", mixed), false);
  });

  it("keeps auto detection signals explicit in the should-run helpers", () => {
    assert.equal(shouldRunNextjsInjectionDetectors("auto", ["common", "nextjs"]), true);
    assert.equal(shouldRunNextjsInjectionDetectors("auto", ["common", "swift"]), false);
    assert.equal(shouldRunSwiftInjectionDetectors("auto", ["common", "swift"]), true);
    assert.equal(shouldRunSwiftInjectionDetectors("auto", ["common", "nextjs"]), false);
    assert.equal(shouldRunNextjsInjectionDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsInjectionDetectors("typescript"), false);
    assert.equal(shouldRunSwiftInjectionDetectors("swift"), true);
    assert.equal(shouldRunSwiftInjectionDetectors("expo"), false);
  });

  it("applies explicit extension applicability instead of every non-Swift file", () => {
    assert.equal(injectionPatternAppliesToFile({ extensions: [".swift"] }, ".swift"), true);
    assert.equal(injectionPatternAppliesToFile({ extensions: [".swift"] }, ".ts"), false);
    assert.equal(injectionPatternAppliesToFile({ extensions: [".swift"] }, ".plist"), false);
    assert.equal(injectionPatternAppliesToFile({}, ".ts"), true);
    assert.equal(injectionPatternAppliesToFile({}, ".tsx"), true);
    assert.equal(injectionPatternAppliesToFile({}, ".js"), true);
    assert.equal(injectionPatternAppliesToFile({}, ".swift"), false);
    assert.equal(injectionPatternAppliesToFile({}, ".md"), false);
    assert.equal(injectionPatternAppliesToFile({ extensions: [".plist", ".xml"] }, ".plist"), true);
    assert.equal(injectionPatternAppliesToFile({ extensions: [".plist", ".xml"] }, ".xml"), true);
    assert.equal(injectionPatternAppliesToFile({ extensions: [".plist", ".xml"] }, ".swift"), false);
  });

  it("derives applied packs from families that evaluated content", () => {
    assert.deepEqual(appliedInjectionPackIds([]), []);
    assert.deepEqual(appliedInjectionPackIds(["core.injection"]), ["core"]);
    assert.deepEqual(appliedInjectionPackIds(["core.injection", "web-next.injection"]), [
      "core",
      "web-next",
    ]);
    assert.deepEqual(
      appliedInjectionPackIds([
        "swift-ios.injection",
        "swift-ios.configuration",
        "swift-ios.cryptography",
      ]),
      ["swift-ios"],
    );
  });

  it("keeps consulted packs separate from applied packs", () => {
    assert.deepEqual(injectionPackIdsForStack("auto", ["common", "swift"]), [
      "core",
      "swift-ios",
    ]);
    assert.deepEqual(injectionPackIdsForStack("swift"), ["swift-ios"]);
    assert.deepEqual(injectionPackIdsForStack("nextjs"), ["core", "web-next"]);
  });
});

async function withTempTree(run: (root: string) => Promise<void>): Promise<void> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-inj-"));
  try {
    await run(root);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

async function runInjectionScan(
  root: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const server = createServer({
    name: "secure-mcp-test",
    version: "test",
    defaultMaxFiles: 50,
    maxFileBytes: 64 * 1024,
    maxDepth: 12,
  });
  const client = new Client({ name: "secure-mcp-test-client", version: "test" });
  try {
    await server.connect(serverTransport);
    await client.connect(clientTransport);
    const result = await client.callTool({
      name: "secure_mcp_analyze_injection_risks",
      arguments: { project_root: root, response_format: "json", ...args },
    });
    assert.equal(result.isError, undefined);
    return result.structuredContent as Record<string, unknown>;
  } finally {
    await client.close();
    await server.close();
  }
}

function rootControls(data: Record<string, unknown>): string[] {
  return ((data.findings as Array<{ root_control?: string }>) ?? [])
    .map((finding) => finding.root_control ?? "")
    .filter(Boolean);
}

function excludedReasons(data: Record<string, unknown>): string[] {
  return (
    ((data.coverage as { excluded_paths?: Array<{ reason: string }> })?.excluded_paths ?? [])
      .map((item) => item.reason)
      .filter(Boolean) ?? []
  );
}

type FamilyTraceability = {
  detector_families_run: string[];
  detector_families_not_run: string[];
};

function familyTraceability(data: Record<string, unknown>): FamilyTraceability {
  const trace = data.knowledge_pack_traceability as Partial<FamilyTraceability> | undefined;
  return {
    detector_families_run: trace?.detector_families_run ?? [],
    detector_families_not_run: trace?.detector_families_not_run ?? [],
  };
}

/** F3: run and not_run are sorted; not_run is available-but-not-run only. */
function assertSortedFamilyTraceability(
  data: Record<string, unknown>,
  expectedAvailable: readonly string[],
): void {
  const { detector_families_run: run, detector_families_not_run: notRun } =
    familyTraceability(data);
  assert.deepEqual(run, [...run].sort(), "detector_families_run must be sorted");
  assert.deepEqual(notRun, [...notRun].sort(), "detector_families_not_run must be sorted");
  const runSet = new Set(run);
  for (const family of notRun) {
    assert.ok(!runSet.has(family), `not_run family must not also be run: ${family}`);
  }
  assert.deepEqual(
    [...run, ...notRun].sort(),
    [...expectedAvailable].sort(),
    "run ∪ not_run must equal available configured families",
  );
}

describe("injection scan matrix", () => {
  it("auto mode routes by detected stacks on a pure Swift project", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "Bridge.swift"),
        "import WebKit\nlet bridge = webView.configuration.userContentController.addScriptMessageHandler(self, name: \"native\")\n",
        "utf8",
      );
      const data = await runInjectionScan(root, {});
      const controls = rootControls(data);
      assert.ok(controls.includes("SWIFT-WEBVIEW-HANDLER"));
      assert.ok(!controls.includes("INJ-EVAL"));
      assert.ok(!controls.includes("NEXT-PUBLIC-SECRET"));
      assert.deepEqual(data.applied_pack_ids, ["swift-ios"]);
      assert.deepEqual(
        (data.knowledge_pack_traceability as { consulted_pack_ids: string[] })
          .consulted_pack_ids,
        ["core", "swift-ios"],
      );
      assert.ok(
        familyTraceability(data).detector_families_run.includes("swift-ios.injection"),
      );
      // Auto + pure Swift still configures core (stack-agnostic baseline) but
      // never evaluates it on .swift files — it must appear sorted in not_run.
      assertSortedFamilyTraceability(data, [
        "core.injection",
        "swift-ios.configuration",
        "swift-ios.cryptography",
        "swift-ios.injection",
      ]);
      assert.deepEqual(familyTraceability(data).detector_families_not_run, [
        "core.injection",
      ]);
    });
  });

  it("forced swift excludes the TypeScript inventory in a mixed project", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "Bridge.swift"),
        "webkit.messageHandlers.native.postMessage(token)\n",
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "server.ts"),
        "const value = eval(request.input);\n",
        "utf8",
      );
      const data = await runInjectionScan(root, { stack: "swift" });
      const controls = rootControls(data);
      assert.ok(controls.includes("SWIFT-WEBVIEW-HANDLER"));
      assert.ok(!controls.includes("INJ-EVAL"));
      assert.ok(excludedReasons(data).includes("no_applicable_injection_detectors"));
      assert.deepEqual(data.applied_pack_ids, ["swift-ios"]);
      assert.deepEqual(
        (data.knowledge_pack_traceability as { consulted_pack_ids: string[] })
          .consulted_pack_ids,
        ["swift-ios"],
      );
      assertSortedFamilyTraceability(data, [
        "swift-ios.configuration",
        "swift-ios.cryptography",
        "swift-ios.injection",
      ]);
    });
  });

  it("forced typescript runs core detectors on TS/TSX and never nextjs ones", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "page.tsx"),
        "export const Page = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\nconst x = eval(input);\n",
        "utf8",
      );
      const data = await runInjectionScan(root, { stack: "typescript" });
      const controls = rootControls(data);
      assert.ok(controls.includes("INJ-DANGEROUS-HTML"));
      assert.ok(controls.includes("INJ-EVAL"));
      assert.ok(!controls.includes("NEXT-DANGEROUS-HTML"));
      assert.deepEqual(data.applied_pack_ids, ["core"]);
      // Only core is configured under forced typescript — not_run stays empty
      // and both lists remain sorted (available-but-not-run semantics).
      assertSortedFamilyTraceability(data, ["core.injection"]);
      assert.deepEqual(familyTraceability(data).detector_families_not_run, []);
    });
  });

  it("forced nextjs adds the web-next family to core", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "page.tsx"),
        "export const Page = ({ html }) => <div dangerouslySetInnerHTML={{ __html: html }} />;\n",
        "utf8",
      );
      const data = await runInjectionScan(root, { stack: "nextjs" });
      const controls = rootControls(data);
      assert.ok(controls.includes("INJ-DANGEROUS-HTML"));
      assert.ok(controls.includes("NEXT-DANGEROUS-HTML"));
      assert.deepEqual(data.applied_pack_ids, ["core", "web-next"]);
      assert.deepEqual(
        (data.knowledge_pack_traceability as { consulted_pack_ids: string[] })
          .consulted_pack_ids,
        ["core", "web-next"],
      );
      assertSortedFamilyTraceability(data, ["core.injection", "web-next.injection"]);
      assert.deepEqual(familyTraceability(data).detector_families_not_run, []);
    });
  });

  it("scans security markdown with common patterns and excludes ordinary markdown", async () => {
    await withTempTree(async (root) => {
      const sqlDoc =
        "The handler builds query = `SELECT * FROM users WHERE id = ${input}` directly; see guidance.\n";
      await fs.writeFile(path.join(root, "SECURITY.md"), sqlDoc, "utf8");
      await fs.writeFile(path.join(root, "README.md"), sqlDoc, "utf8");
      const data = await runInjectionScan(root, { stack: "typescript" });
      const controls = rootControls(data);
      assert.ok(controls.includes("INJ-SQL-CONCAT"));
      assert.ok(excludedReasons(data).includes("non_security_documentation"));
      assert.ok(
        ((data.files_reviewed as string[]) ?? []).includes("SECURITY.md"),
        "security markdown must be reviewed",
      );
      assert.ok(!((data.files_reviewed as string[]) ?? []).includes("README.md"));
    });
  });

  it("applies configuration detectors only to configuration files under swift", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "Info.plist"),
        "<dict><key>NSAllowsArbitraryLoads</key><true/></dict>\n",
        "utf8",
      );
      const data = await runInjectionScan(root, { stack: "swift" });
      assert.ok(rootControls(data).includes("SWIFT-ATS-ARBITRARY"));
      assert.ok(
        familyTraceability(data).detector_families_run.includes("swift-ios.configuration"),
      );
      assertSortedFamilyTraceability(data, [
        "swift-ios.configuration",
        "swift-ios.cryptography",
        "swift-ios.injection",
      ]);
    });
  });

  it("records zero-applicability exclusions for files outside every family", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(path.join(root, "config.xml"), "<root/>\n", "utf8");
      await fs.writeFile(path.join(root, "index.html"), "<html></html>\n", "utf8");
      const data = await runInjectionScan(root, { stack: "typescript" });
      const reasons = excludedReasons(data);
      assert.ok(
        reasons.filter((reason) => reason === "no_applicable_injection_detectors").length >= 2,
      );
      assert.deepEqual(data.applied_pack_ids, []);
      assert.deepEqual(data.findings, []);
      // Configured core never evaluated any content → entirely in not_run, sorted.
      assertSortedFamilyTraceability(data, ["core.injection"]);
      assert.deepEqual(familyTraceability(data).detector_families_not_run, [
        "core.injection",
      ]);
      assert.deepEqual(familyTraceability(data).detector_families_run, []);
    });
  });

  it("accounts read failures as exclusions without fabricating findings", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "eval.ts"),
        "const value = eval(request.input);\n",
        "utf8",
      );
      await fs.writeFile(path.join(root, "unreadable.ts"), "const x = 1;\n", "utf8");
      await fs.chmod(path.join(root, "unreadable.ts"), 0o000);
      try {
        const data = await runInjectionScan(root, { stack: "typescript" });
        assert.ok(excludedReasons(data).includes("file_read_error"));
        assert.ok(rootControls(data).includes("INJ-EVAL"));
      } finally {
        await fs.chmod(path.join(root, "unreadable.ts"), 0o644);
      }
    });
  });

  it("mixed projects under auto apply both core and swift families", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "server.ts"),
        "const value = eval(request.input);\n",
        "utf8",
      );
      await fs.writeFile(
        path.join(root, "Bridge.swift"),
        "webkit.messageHandlers.native.postMessage(token)\n",
        "utf8",
      );
      const data = await runInjectionScan(root, {});
      const controls = rootControls(data);
      assert.ok(controls.includes("INJ-EVAL"));
      assert.ok(controls.includes("SWIFT-WEBVIEW-HANDLER"));
      assert.deepEqual(data.applied_pack_ids, ["core", "swift-ios"]);
    });
  });

  it("forced common runs only the common core pattern", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(
        path.join(root, "server.ts"),
        "const value = eval(request.input);\nconst q = query = `SELECT * FROM t WHERE id = ${id}`;\n",
        "utf8",
      );
      const data = await runInjectionScan(root, { stack: "common" });
      const controls = rootControls(data);
      assert.ok(controls.includes("INJ-SQL-CONCAT"));
      assert.ok(!controls.includes("INJ-EVAL"));
      assert.deepEqual(data.applied_pack_ids, ["core"]);
    });
  });
});
