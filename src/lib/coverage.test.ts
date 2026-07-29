import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  boundStructuredPayload,
  CHARACTER_LIMIT,
  readProjectFile,
  recordCoverageExclusion,
  walkProject,
} from "./filesystem.js";

async function withTempTree(run: (root: string, outside: string) => Promise<void>): Promise<void> {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-coverage-"));
  const outside = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-outside-"));
  try {
    await run(root, outside);
  } finally {
    await fs.rm(root, { recursive: true, force: true });
    await fs.rm(outside, { recursive: true, force: true });
  }
}

describe("bounded coverage accounting", () => {
  it("keeps the repository security policy readable as review guidance", async () => {
    const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
    const policy = await readProjectFile(repositoryRoot, "SECURITY.md");
    assert.match(policy.content, /defensive, read-only/i);
    assert.match(policy.content, /does not execute target-project code/i);
  });

  it("includes SECURITY.md and reports ignored files, caps, and truncation", async () => {
    await withTempTree(async (root) => {
      await fs.writeFile(path.join(root, "SECURITY.md"), "# Security policy\n", "utf8");
      await fs.writeFile(path.join(root, ".env.local"), "TOKEN=redacted-fixture\n", "utf8");
      await fs.writeFile(path.join(root, "a.ts"), "export const a = 1;\n", "utf8");
      await fs.writeFile(path.join(root, "b.ts"), "export const b = 1;\n", "utf8");
      await fs.mkdir(path.join(root, "node_modules"));
      await fs.writeFile(path.join(root, "node_modules", "ignored.ts"), "ignored", "utf8");
      await fs.writeFile(path.join(root, "pnpm-lock.yaml"), "ignored", "utf8");

      const result = await walkProject(root, { maxFiles: 1 });
      assert.equal(result.files.length, 1);
      assert.equal(result.coverage.truncation.truncated, true);
      assert.ok(result.coverage.truncation.reasons.includes("max_files"));
      assert.equal(result.coverage.caps.max_files, 1);
      assert.equal(result.coverage.not_observed_means, "scope_was_truncated_or_partial");

      const full = await walkProject(root);
      assert.ok(full.files.some((file) => file.relativePath === "SECURITY.md"));
      assert.ok(full.files.some((file) => file.relativePath === ".env.local"));
      assert.ok(full.coverage.ignored_paths.some((item) => item.path === "node_modules"));
      assert.ok(full.coverage.ignored_paths.some((item) => item.path === "pnpm-lock.yaml"));
    });
  });

  it("accounts for size caps and rejects symlink escapes", async () => {
    await withTempTree(async (root, outside) => {
      await fs.writeFile(path.join(root, "large.ts"), "123456789", "utf8");
      await fs.writeFile(path.join(outside, "secret.ts"), "outside", "utf8");
      await fs.symlink(path.join(outside, "secret.ts"), path.join(root, "link.ts"));

      const result = await walkProject(root, { maxFileBytes: 4 });
      assert.ok(
        result.coverage.excluded_paths.some(
          (item) => item.path === "large.ts" && item.reason === "max_file_bytes",
        ),
      );
      assert.ok(
        result.coverage.excluded_paths.some(
          (item) => item.path === "link.ts" && item.reason === "symlink_target_outside_root",
        ),
      );
      await assert.rejects(
        () => readProjectFile(root, "link.ts"),
        /symlink|project root/i,
      );
    });
  });

  it("rejects symlinked directories that point outside the review root", async () => {
    await withTempTree(async (root, outside) => {
      await fs.writeFile(path.join(outside, "secret.ts"), "export const secret = 1;\n", "utf8");
      await fs.symlink(outside, path.join(root, "linked-src"));

      const result = await walkProject(root);
      assert.ok(
        result.coverage.excluded_paths.some(
          (item) => item.path === "linked-src" && item.reason === "symlink_target_outside_root",
        ),
      );
      assert.ok(!result.files.some((file) => file.relativePath.includes("linked-src/")));
      assert.ok(result.coverage.truncation.reasons.includes("symlink_containment"));
      assert.equal(result.coverage.not_observed_means, "scope_was_truncated_or_partial");
    });
  });

  it("marks omitted coverage events and never reports complete when the event cap is hit", async () => {
    await withTempTree(async (root) => {
      for (let i = 0; i < 6; i++) {
        await fs.writeFile(path.join(root, `f${i}.ts`), `export const n = ${i};\n`, "utf8");
      }
      const result = await walkProject(root, {
        maxFiles: 50,
        maxCoverageEvents: 2,
        extensions: new Set([".ts"]),
      });
      assert.equal(result.coverage.truncation.coverage_events_truncated, true);
      assert.ok(result.coverage.truncation.reasons.includes("included_paths_cap"));
      assert.notEqual(result.coverage.scan_status, "complete");
      assert.equal(result.coverage.not_observed_means, "scope_was_truncated_or_partial");
      assert.ok(result.coverage.included_paths.length <= 2);
      assert.ok(
        result.coverage.excluded_paths.some((item) => item.reason === "included_paths_cap"),
      );
    });
  });

  it("marks coverage_events_truncated when recordCoverageExclusion overflows", () => {
    const coverage = {
      included_paths: [],
      excluded_paths: [
        { path: "a", kind: "file" as const, reason: "x" },
        { path: "b", kind: "file" as const, reason: "x" },
      ],
      ignored_paths: [],
      caps: { max_files: 10, max_depth: 5, max_file_bytes: 100 },
      truncation: { truncated: false, reasons: [], coverage_events_truncated: false },
      files_reviewed: [],
      candidate_dispositions: [],
      candidate_disposition_counts: {
        reportable: 0,
        needs_review: 0,
        suppressed: 0,
        not_applicable: 0,
        deferred: 0,
      },
      scan_status: "complete" as const,
      not_observed_means: "no_candidate_in_files_reviewed" as const,
    };
    recordCoverageExclusion(
      coverage,
      { path: "c", kind: "file", reason: "extra" },
      2,
    );
    assert.equal(coverage.truncation.coverage_events_truncated, true);
    assert.ok(coverage.truncation.reasons.includes("coverage_events_cap"));
    assert.notEqual(coverage.scan_status, "complete");
  });

  it("bounds structured tool payloads, not only text", () => {
    const findings = Array.from({ length: 200 }, (_, i) => ({
      id: `F-${i}`,
      title: "x".repeat(80),
      evidence: "y".repeat(120),
    }));
    const { data, truncated } = boundStructuredPayload(
      { ok: true, summary: "large", findings },
      2_000,
    );
    assert.equal(truncated, true);
    assert.ok(JSON.stringify(data).length <= 2_000 + 200); // small slack for last-resort envelope
    assert.ok(Array.isArray((data as { findings?: unknown[] }).findings));
    assert.ok(((data as { findings?: unknown[] }).findings?.length ?? 0) < findings.length);
    assert.ok(JSON.stringify(data).length < CHARACTER_LIMIT);
  });

  it("bounds payloads dominated by nested coverage arrays", () => {
    const limit = 2_000;
    const paths = Array.from({ length: 500 }, (_, i) => `src/module-${i}/file-${i}.ts`);
    const payload = {
      ok: true as const,
      summary: "coverage-heavy",
      findings: [{ id: "F-1", title: "small" }],
      coverage: {
        included_paths: paths,
        excluded_paths: paths.map((p) => ({ path: p, kind: "file" as const, reason: "sample" })),
        ignored_paths: paths.slice(0, 100).map((p) => ({
          path: p,
          kind: "file" as const,
          reason: "ignored",
        })),
        caps: { max_files: 500, max_depth: 12, max_file_bytes: 100_000 },
        truncation: { truncated: false, reasons: [] as string[], coverage_events_truncated: false },
        files_reviewed: paths,
        candidate_dispositions: paths.map((p, i) => ({
          id: `C-${i}`,
          disposition: "needs_review" as const,
          reason: "needs confirmation",
          file: p,
        })),
        candidate_disposition_counts: {
          reportable: 0,
          needs_review: paths.length,
          suppressed: 0,
          not_applicable: 0,
          deferred: 0,
        },
        scan_status: "complete" as const,
        not_observed_means: "no_candidate_in_files_reviewed" as const,
      },
    };
    assert.ok(JSON.stringify(payload).length > limit);
    const { data, truncated } = boundStructuredPayload(payload, limit);
    assert.equal(truncated, true);
    const encoded = JSON.stringify(data);
    assert.ok(encoded.length <= limit, `encoded length ${encoded.length} exceeds limit ${limit}`);
    const coverage = (data as { coverage?: { included_paths?: unknown[]; files_reviewed?: unknown[] } })
      .coverage;
    if (coverage) {
      assert.ok((coverage.included_paths?.length ?? 0) < paths.length);
      assert.ok((coverage.files_reviewed?.length ?? 0) < paths.length);
    }
  });

  it("reads only up to maxBytes without requiring a full in-memory copy for large files", async () => {
    await withTempTree(async (root) => {
      const payload = "A".repeat(64 * 1024);
      await fs.writeFile(path.join(root, "big.ts"), payload, "utf8");
      const result = await readProjectFile(root, "big.ts", 1024);
      assert.equal(result.truncated, true);
      assert.equal(result.size, payload.length);
      assert.ok(Buffer.byteLength(result.content, "utf8") <= 1024);
    });
  });
});
