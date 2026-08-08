/**
 * Conservative filesystem helpers for local code audits.
 *
 * Design goals:
 * - Never escape the requested project root
 * - Never execute user code
 * - Cap file size, tree depth, and total files to keep agents usable on large repos
 */

import { constants as fsConstants, promises as fs, type Stats } from "node:fs";
import type { FileHandle } from "node:fs/promises";
import path from "node:path";
import type {
  CandidateDisposition,
  CoverageCandidateDisposition,
  CoveragePathDecision,
  CoverageReport,
  Finding,
  ProjectProfile,
  StackFocus,
} from "./types.js";
import { CANDIDATE_DISPOSITIONS } from "./types.js";
import { redactValue, redactedEvidence, UNTRUSTED_OUTPUT_NOTICE } from "./redact.js";

/** Default directories/files to skip when walking a project. */
export const DEFAULT_IGNORE_DIRS = new Set([
  "node_modules",
  ".git",
  ".svn",
  ".hg",
  "dist",
  "build",
  "out",
  ".next",
  ".nuxt",
  ".turbo",
  ".cache",
  "coverage",
  "vendor",
  "Pods",
  "DerivedData",
  ".build",
  "xcuserdata",
  ".gradle",
  "target",
  "__pycache__",
  ".venv",
  "venv",
  ".idea",
  ".vscode",
  "tmp",
  "temp",
]);

export const DEFAULT_IGNORE_FILES = new Set([
  ".DS_Store",
  "package-lock.json",
  "pnpm-lock.yaml",
  "yarn.lock",
  "bun.lockb",
  "Package.resolved",
]);

/** Extensions commonly useful for security review. */
export const CODE_EXTENSIONS = new Set([
  ".ts",
  ".tsx",
  ".js",
  ".jsx",
  ".mjs",
  ".cjs",
  ".swift",
  ".json",
  ".yml",
  ".yaml",
  ".env",
  ".md",
  ".html",
  ".css",
  ".scss",
  ".sql",
  ".graphql",
  ".gql",
  ".toml",
  ".plist",
  ".entitlements",
  ".pbxproj",
]);

export const DEFAULT_MAX_FILE_BYTES = 256 * 1024; // 256 KiB per file
export const DEFAULT_MAX_FILES = 400;
export const DEFAULT_MAX_DEPTH = 12;
export const DEFAULT_MAX_TOTAL_BYTES = 64 * 1024 * 1024;
export const HARD_MAX_FILES = 1_000;
export const HARD_MAX_FILE_BYTES = 1 * 1024 * 1024;
export const HARD_MAX_DEPTH = 20;
export const HARD_MAX_TOTAL_BYTES = 128 * 1024 * 1024;
export const CHARACTER_LIMIT = 25_000;

export interface WalkOptions {
  maxFiles?: number;
  maxDepth?: number;
  extensions?: Set<string> | null;
  ignoreDirs?: Set<string>;
  ignoreFiles?: Set<string>;
  /** Additional relative path prefixes to skip (posix-style). */
  extraIgnorePrefixes?: string[];
  /** Optional focus: only include files whose rel path matches one of these prefixes (for scoped drill-down). */
  focusPrefixes?: string[];
  /** Files larger than this are accounted for but not returned for review. */
  maxFileBytes?: number;
  /** Aggregate byte budget for files included in this walk. */
  maxTotalBytes?: number;
  /** Optional canonical-root allowlist for process-level tool calls. */
  allowedRoots?: readonly string[];
  /** Cap on coverage path events retained in the report (default 1000). */
  maxCoverageEvents?: number;
}

export interface ProfileOptions {
  /** When set, language sampling walks only these relative prefixes. */
  focusPrefixes?: string[];
  /** Optional scan limits inherited from the server configuration. */
  maxFiles?: number;
  maxDepth?: number;
  maxFileBytes?: number;
  maxTotalBytes?: number;
  /** Optional canonical-root allowlist for process-level tool calls. */
  allowedRoots?: readonly string[];
}

interface TopLevelInspection {
  entries: string[];
  truncated: boolean;
  hasXcodeProject: boolean;
  hasAndroidDirectory: boolean;
  hasIosDirectory: boolean;
  hasAppDirectory: boolean;
  hasPagesDirectory: boolean;
}

export interface FileEntry {
  /** Absolute path. */
  absolutePath: string;
  /** Path relative to project root (posix separators). */
  relativePath: string;
  size: number;
  ext: string;
}

export interface ReadFileResult {
  relativePath: string;
  content: string;
  truncated: boolean;
  size: number;
}

/**
 * Resolve and validate that target stays inside project root.
 * Throws with an actionable message on path traversal attempts.
 */
export function resolveSafePath(projectRoot: string, maybeRelative: string): string {
  const root = path.resolve(projectRoot);
  const resolved = path.resolve(root, maybeRelative);
  const rel = path.relative(root, resolved);
  if (rel.startsWith("..") || path.isAbsolute(rel)) {
    throw new Error(
      `Path escapes project root: "${maybeRelative}". Provide a path inside ${root}.`,
    );
  }
  return resolved;
}

function isWithinRoot(root: string, target: string): boolean {
  const relative = path.relative(root, target);
  return relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative));
}

/** Normalize project root to an absolute existing directory. */
export async function normalizeProjectRoot(projectRoot: string): Promise<string> {
  if (!projectRoot || !projectRoot.trim()) {
    throw new Error(
      'Missing project_root. Pass an absolute path (or path relative to the MCP process cwd).',
    );
  }
  const absolute = path.resolve(projectRoot.trim());
  let handle: FileHandle | undefined;
  try {
    const initialRealPath = await fs.realpath(absolute);
    // Open first and take metadata from the descriptor. The follow-enabled
    // root open preserves the supported behavior where the requested root
    // itself is a symlink, while the identity check rejects a root replacement
    // between validation and canonicalization.
    handle = await fs.open(
      absolute,
      fsConstants.O_RDONLY | fsConstants.O_DIRECTORY | fsConstants.O_NONBLOCK,
    );
    const opened = await handle.stat();
    if (!opened.isDirectory()) {
      throw new Error(`project_root is not a directory: ${absolute}`);
    }
    const current = await fs.stat(absolute);
    if (!sameFilesystemObject(opened, current)) {
      throw changedPathError(absolute);
    }
    const finalRealPath = await fs.realpath(absolute);
    if (finalRealPath !== initialRealPath) {
      throw changedPathError(absolute);
    }
    return finalRealPath;
  } catch (error) {
    if (error instanceof Error && /not a directory|changed while/i.test(error.message)) {
      throw error;
    }
    throw new Error(
      `project_root does not exist: ${absolute}. Check the path and that the MCP process can access it.`,
    );
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/**
 * Normalize a project root and enforce the process filesystem allowlist.
 * Programmatic configs may omit allowedRoots for backwards-compatible tests;
 * loadConfig supplies an empty list when the operator has not
 * configured one, which fails closed.
 */
export async function normalizeAuthorizedProjectRoot(
  projectRoot: string,
  allowedRoots?: readonly string[],
): Promise<string> {
  const root = await normalizeProjectRoot(projectRoot);
  if (allowedRoots === undefined) return root;
  if (allowedRoots.length === 0) {
    throw new Error("No allowed project roots are configured for this server.");
  }

  for (const allowedRoot of allowedRoots) {
    try {
      const canonicalAllowedRoot = await normalizeProjectRoot(allowedRoot);
      if (isWithinRoot(canonicalAllowedRoot, root)) return root;
    } catch {
      // Ignore stale allowlist entries; a valid configured root can still match.
    }
  }
  throw new Error("project_root is outside the server's configured allowed roots.");
}

function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

function ignoreReason(
  name: string,
  isDir: boolean,
  ignoreDirs: Set<string>,
  ignoreFiles: Set<string>,
): string | null {
  if (name.startsWith(".") && name !== ".env" && name !== ".env.example" && name !== ".env.local") {
    if (isDir || !name.startsWith(".env")) {
      if (name !== ".github" && name !== ".env" && isDir) return "hidden_directory";
    }
  }
  if (isDir && ignoreDirs.has(name)) return "configured_ignored_directory";
  if (!isDir && ignoreFiles.has(name)) return "configured_ignored_file";
  return null;
}

function normalizePrefix(p: string): string {
  return p.replace(/^\/+|\/+$/g, "");
}

function matchesFocus(rel: string, prefixes: string[]): boolean {
  if (!prefixes || prefixes.length === 0) return true;
  const r = rel.replace(/^\//, "");
  return prefixes.some((raw) => {
    const pp = normalizePrefix(raw);
    if (!pp) return true;
    if (r === pp) return true;
    if (r.startsWith(pp + "/")) return true;
    return false;
  });
}

function dirLeadsToAnyFocus(dirRel: string, prefixes: string[]): boolean {
  if (!prefixes || prefixes.length === 0) return true;
  const d = normalizePrefix(dirRel);
  return prefixes.some((raw) => {
    const pp = normalizePrefix(raw);
    if (!pp) return true;
    if (d === "" || d === pp) return true;
    if (pp.startsWith(d + "/")) return true;
    if (d.startsWith(pp + "/")) return true;
    return false;
  });
}

/**
 * Depth-first walk of a project tree with safety caps.
 * Returns files only (not directories).
 */
export async function walkProject(
  projectRoot: string,
  options: WalkOptions = {},
): Promise<{ files: FileEntry[]; truncated: boolean; coverage: CoverageReport }> {
  const root = await normalizeAuthorizedProjectRoot(projectRoot, options.allowedRoots);
  const boundedPositive = (value: number | undefined, fallback: number, maximum: number): number =>
    value !== undefined && Number.isFinite(value) && value > 0
      ? Math.min(value, maximum)
      : fallback;
  const maxFiles = boundedPositive(options.maxFiles, DEFAULT_MAX_FILES, HARD_MAX_FILES);
  const maxDepth = boundedPositive(options.maxDepth, DEFAULT_MAX_DEPTH, HARD_MAX_DEPTH);
  const maxFileBytes = boundedPositive(
    options.maxFileBytes,
    DEFAULT_MAX_FILE_BYTES,
    HARD_MAX_FILE_BYTES,
  );
  const maxTotalBytes = boundedPositive(
    options.maxTotalBytes,
    DEFAULT_MAX_TOTAL_BYTES,
    HARD_MAX_TOTAL_BYTES,
  );
  const extensions = options.extensions === undefined ? CODE_EXTENSIONS : options.extensions;
  const ignoreDirs = options.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const ignoreFiles = options.ignoreFiles ?? DEFAULT_IGNORE_FILES;
  const extraIgnorePrefixes = options.extraIgnorePrefixes ?? [];
  const focusPrefixes = (options.focusPrefixes ?? []).map(normalizePrefix).filter(Boolean);

  const files: FileEntry[] = [];
  let truncated = false;
  const truncationReasons = new Set<string>();
  const excludedPaths: CoveragePathDecision[] = [];
  const ignoredPaths: CoveragePathDecision[] = [];
  let coverageEventsTruncated = false;
  let totalBytes = 0;
  const maxCoverageEvents = options.maxCoverageEvents ?? 1000;

  const markCoverageEventsTruncated = (reason = "coverage_events_cap"): void => {
    coverageEventsTruncated = true;
    truncationReasons.add(reason);
  };

  const addEvent = (
    target: CoveragePathDecision[],
    event: CoveragePathDecision,
  ): void => {
    if (target.length < maxCoverageEvents) target.push(event);
    else markCoverageEventsTruncated("coverage_events_cap");
  };

  /**
   * Classify and record a directory that could not be opened or verified.
   * Reporting is pathname-based (realpath for the reason) but the directory is
   * never enumerated through an unverified handle.
   */
  const recordDirWalkFailure = async (dir: string, error: unknown): Promise<void> => {
    const rel = toPosix(path.relative(root, dir)) || ".";
    const code = (error as NodeJS.ErrnoException).code;
    if (code === CONTAINMENT_CODE) {
      addEvent(excludedPaths, {
        path: rel,
        kind: "directory",
        reason: "symlink_target_outside_root",
      });
      truncationReasons.add("symlink_containment");
      return;
    }
    if (code === PATH_CHANGED_CODE) {
      addEvent(excludedPaths, {
        path: rel,
        kind: "directory",
        reason: "directory_replaced_during_walk",
      });
      truncationReasons.add("directory_replaced_during_walk");
      return;
    }
    if (code === "ELOOP" || code === "EMLINK" || code === "EPERM" || code === "ENOTDIR") {
      const realTarget = await fs.realpath(dir).catch(() => null);
      const reason =
        realTarget !== null && !isWithinRoot(root, realTarget)
          ? "symlink_target_outside_root"
          : "symlink_not_followed";
      addEvent(excludedPaths, { path: rel, kind: "directory", reason });
      if (reason === "symlink_target_outside_root") truncationReasons.add("symlink_containment");
      return;
    }
    addEvent(excludedPaths, {
      path: rel,
      kind: "directory",
      reason: "directory_realpath_error",
    });
  };

  async function walk(dir: string, depth: number): Promise<void> {
    if (truncated) return;
    if (depth > maxDepth) return;

    // Open the directory and verify the OPENED object stays in-root before any
    // enumeration. A raced symlink or swapped intermediate directory is rejected
    // here; enumeration never runs against an unverified pathname.
    let dirHandle: FileHandle | undefined;
    try {
      dirHandle = await fs.open(dir, openDirFlags());
      await verifyOpenedDirHandle(dirHandle, dir, root);
    } catch (error) {
      await dirHandle?.close().catch(() => undefined);
      await recordDirWalkFailure(dir, error);
      return;
    }

    let verifiedDir: string;
    try {
      // Use the canonical path of the already-verified directory object for
      // enumeration. The original mutable pathname is checked again after the
      // read and the entire entry set is discarded if its object changed.
      verifiedDir = await verifyOpenedDirHandle(dirHandle, dir, root);
    } catch (error) {
      await dirHandle?.close().catch(() => undefined);
      await recordDirWalkFailure(dir, error);
      return;
    }

    let entries;
    try {
      entries = await fs.readdir(verifiedDir, { withFileTypes: true });
    } catch {
      await dirHandle?.close().catch(() => undefined);
      addEvent(excludedPaths, {
        path: toPosix(path.relative(root, dir)) || ".",
        kind: "directory",
        reason: "directory_read_error",
      });
      return;
    }

    // Re-verify after enumeration: if the directory was replaced while entries
    // were being read, the names are not trustworthy and are discarded.
    try {
      await verifyOpenedDirHandle(dirHandle, dir, root);
    } catch (error) {
      await recordDirWalkFailure(dir, error);
      return;
    } finally {
      await dirHandle?.close().catch(() => undefined);
    }

    // Stable order for reproducible agent output
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (truncated) return;
      const abs = path.join(dir, entry.name);
      const rel = toPosix(path.relative(root, abs));

      if (extraIgnorePrefixes.some((p) => rel === p || rel.startsWith(`${p}/`))) {
        addEvent(ignoredPaths, {
          path: rel,
          kind: entry.isDirectory() ? "directory" : "file",
          reason: "extra_ignore_prefix",
        });
        continue;
      }

      // focus scoping: prune files and dirs that do not match
      if (focusPrefixes.length > 0) {
        const isDir = entry.isDirectory();
        if (isDir) {
          if (!dirLeadsToAnyFocus(rel, focusPrefixes)) {
            addEvent(excludedPaths, { path: rel, kind: "directory", reason: "outside_focus_paths" });
            continue;
          }
        } else {
          if (!matchesFocus(rel, focusPrefixes)) {
            addEvent(excludedPaths, { path: rel, kind: "file", reason: "outside_focus_paths" });
            continue;
          }
        }
      }

      const reason = ignoreReason(entry.name, entry.isDirectory(), ignoreDirs, ignoreFiles);
      if (reason) {
        addEvent(ignoredPaths, {
          path: rel,
          kind: entry.isDirectory() ? "directory" : "file",
          reason,
        });
        continue;
      }

      if (entry.isSymbolicLink()) {
        try {
          const realTarget = await fs.realpath(abs);
          addEvent(excludedPaths, {
            path: rel,
            kind: "symlink",
            reason: isWithinRoot(root, realTarget)
              ? "symlink_not_followed"
              : "symlink_target_outside_root",
          });
          if (!isWithinRoot(root, realTarget)) truncationReasons.add("symlink_containment");
        } catch {
          addEvent(excludedPaths, { path: rel, kind: "symlink", reason: "symlink_unresolvable" });
        }
        continue;
      }

      if (entry.isDirectory()) {
        if (depth >= maxDepth) {
          truncated = true;
          truncationReasons.add("max_depth");
          addEvent(excludedPaths, { path: rel, kind: "directory", reason: "max_depth" });
          continue;
        }
        // walk() opens and verifies the directory itself; a raced symlink or
        // swapped directory is recorded there and never descended into.
        await walk(abs, depth + 1);
        continue;
      }

      if (!entry.isFile()) {
        addEvent(excludedPaths, { path: rel, kind: "other", reason: "not_a_regular_file" });
        continue;
      }

      const ext =
        entry.name === ".env" || entry.name.startsWith(".env.")
          ? ".env"
          : path.extname(entry.name).toLowerCase();
      if (extensions && extensions.size > 0 && !extensions.has(ext)) {
        // Always allow extensionless suspicious names like Dockerfile? skip for v1.
        if (entry.name !== "Dockerfile" && entry.name !== "Makefile") {
          addEvent(excludedPaths, { path: rel, kind: "file", reason: "extension_not_in_scope" });
          continue;
        }
      }

      // Size and containment are taken from a verified, opened descriptor so a
      // raced swap cannot report metadata for an object outside the root.
      let size = 0;
      try {
        const realFile = await fs.realpath(abs);
        if (!isWithinRoot(root, realFile)) throw containmentError(abs);
        if (realFile !== path.normalize(abs)) {
          addEvent(excludedPaths, {
            path: rel,
            kind: "symlink",
            reason: "symlink_not_followed",
          });
          continue;
        }
        const opened = await openCanonicalPath(root, realFile, openReadFlags(), "file");
        try {
          size = opened.stat.size;
        } finally {
          await opened.handle.close().catch(() => undefined);
        }
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        if (code === PATH_CHANGED_CODE) {
          addEvent(excludedPaths, {
            path: rel,
            kind: "file",
            reason: "file_replaced_during_walk",
          });
          truncationReasons.add("file_replaced_during_walk");
          continue;
        }
        if (
          code === CONTAINMENT_CODE ||
          code === "ELOOP" ||
          code === "EMLINK" ||
          code === "EPERM"
        ) {
          const realTarget = await fs.realpath(abs).catch(() => null);
          const reason =
            realTarget !== null && !isWithinRoot(root, realTarget)
              ? "symlink_target_outside_root"
              : "symlink_unresolvable";
          addEvent(excludedPaths, { path: rel, kind: "symlink", reason });
          if (reason === "symlink_target_outside_root") truncationReasons.add("symlink_containment");
          continue;
        }
        addEvent(excludedPaths, {
          path: rel,
          kind: "file",
          reason: code === "EACCES" ? "file_read_error" : "file_stat_error",
        });
        continue;
      }

      if (size > maxFileBytes) {
        truncationReasons.add("max_file_bytes");
        addEvent(excludedPaths, { path: rel, kind: "file", reason: "max_file_bytes" });
        continue;
      }

      if (totalBytes + size > maxTotalBytes) {
        truncated = true;
        truncationReasons.add("max_total_bytes");
        addEvent(excludedPaths, { path: rel, kind: "file", reason: "max_total_bytes" });
        continue;
      }

      files.push({ absolutePath: abs, relativePath: rel, size, ext });
      totalBytes += size;
      if (files.length > maxCoverageEvents) {
        markCoverageEventsTruncated("included_paths_cap");
      }
      if (files.length >= maxFiles) {
        truncated = true;
        truncationReasons.add("max_files");
        return;
      }
    }
  }

  await walk(root, 0);
  const includedPaths = files.slice(0, maxCoverageEvents).map((file) => file.relativePath);
  if (files.length > maxCoverageEvents) {
    markCoverageEventsTruncated("included_paths_cap");
    addEvent(excludedPaths, {
      path: "[omitted-included-paths]",
      kind: "other",
      reason: "included_paths_cap",
    });
  }
  const walkTruncated =
    truncated ||
    truncationReasons.has("max_files") ||
    truncationReasons.has("max_depth") ||
    truncationReasons.has("max_file_bytes") ||
    truncationReasons.has("max_total_bytes") ||
    truncationReasons.has("symlink_containment") ||
    truncationReasons.has("response_size");
  const effectiveTruncated = walkTruncated;
  const hasScopeGaps =
    effectiveTruncated ||
    coverageEventsTruncated ||
    excludedPaths.length > 0 ||
    ignoredPaths.length > 0;
  const candidateDispositionCounts = Object.fromEntries(
    CANDIDATE_DISPOSITIONS.map((disposition) => [disposition, 0]),
  ) as Record<CandidateDisposition, number>;
  const scan_status: CoverageReport["scan_status"] = effectiveTruncated
    ? "truncated"
    : hasScopeGaps
      ? "partial"
      : "complete";
  return {
    files,
    truncated: effectiveTruncated || coverageEventsTruncated,
    coverage: {
      included_paths: includedPaths,
      excluded_paths: excludedPaths,
      ignored_paths: ignoredPaths,
      caps: {
        max_files: maxFiles,
        max_depth: maxDepth,
        max_file_bytes: maxFileBytes,
        max_total_bytes: maxTotalBytes,
      },
      truncation: {
        truncated: effectiveTruncated || coverageEventsTruncated,
        reasons: [...truncationReasons],
        coverage_events_truncated: coverageEventsTruncated,
      },
      files_reviewed: [],
      candidate_dispositions: [],
      candidate_disposition_counts: candidateDispositionCounts,
      scan_status,
      // The walk is inventory only: contents are never opened here. Content-review
      // finalizers (finalizeCoverage) upgrade this; inventory finalizers keep it.
      review_basis: "inventory_only",
      not_observed_means:
        scan_status === "complete"
          ? "inventory_only_contents_not_reviewed"
          : "scope_was_truncated_or_partial",
    },
  };
}

/** Add a scanner-specific exclusion while keeping the walk's accounting honest. */
export function recordCoverageExclusion(
  coverage: CoverageReport,
  event: CoveragePathDecision,
  maxCoverageEvents = 1000,
): void {
  if (coverage.excluded_paths.length < maxCoverageEvents) {
    coverage.excluded_paths.push(event);
  } else {
    coverage.truncation.coverage_events_truncated = true;
    coverage.truncation.reasons = [
      ...new Set([...coverage.truncation.reasons, "coverage_events_cap"]),
    ];
  }
  coverage.truncation.reasons = [...new Set([...coverage.truncation.reasons, event.reason])];
  if (
    [
      "max_files",
      "max_depth",
      "max_file_bytes",
      "max_total_bytes",
      "response_size",
      "symlink_containment",
      "coverage_events_cap",
      "included_paths_cap",
    ].includes(event.reason)
  ) {
    coverage.truncation.truncated = true;
  }
  if (coverage.truncation.coverage_events_truncated && !coverage.truncation.truncated) {
    // Omitted accounting events make the report incomplete even when the walk finished.
  }
  coverage.scan_status = coverage.truncation.truncated
    ? "truncated"
    : coverage.truncation.coverage_events_truncated
      ? "partial"
      : "partial";
  coverage.not_observed_means = "scope_was_truncated_or_partial";
}

/** Finalize a walk report with the files actually opened and candidate decisions. */
export function finalizeCoverage(
  coverage: CoverageReport,
  filesReviewed: readonly string[],
  candidates: ReadonlyArray<
    Pick<Finding, "id" | "disposition" | "disposition_reason" | "file" | "line" | "rule_family" | "instance_id">
  > = [],
): CoverageReport {
  const dispositions: CoverageCandidateDisposition[] = candidates.map((candidate) => ({
    id: candidate.id,
    disposition: candidate.disposition ?? "needs_review",
    reason:
      candidate.disposition_reason ??
      "Candidate requires confirmation before it is treated as a reportable finding.",
    ...(candidate.file ? { file: candidate.file } : {}),
    ...(candidate.line ? { line: candidate.line } : {}),
    ...(candidate.rule_family ? { rule_family: candidate.rule_family } : {}),
    ...(candidate.instance_id ? { instance_id: candidate.instance_id } : {}),
  }));
  const counts = Object.fromEntries(
    CANDIDATE_DISPOSITIONS.map((disposition) => [disposition, 0]),
  ) as Record<CandidateDisposition, number>;
  for (const candidate of dispositions) counts[candidate.disposition]++;
  const reviewed = [...new Set(filesReviewed)];
  coverage.files_reviewed = reviewed;

  // A caller can only claim content coverage for files it actually opened and
  // evaluated. An empty receipt set is inventory-only, even when the walk had
  // no path exclusions. Likewise, a partial receipt set must not inherit a
  // clean inventory's `complete` status.
  const included = new Set(coverage.included_paths);
  const allIncludedReviewed =
    reviewed.length > 0 && [...included].every((file) => reviewed.includes(file));
  if (reviewed.length === 0) {
    coverage.review_basis = "inventory_only";
    coverage.scan_status = coverage.truncation.truncated ? "truncated" : "partial";
    coverage.not_observed_means = "inventory_only_contents_not_reviewed";
  } else {
    coverage.review_basis = "content_review";
    if (!allIncludedReviewed && coverage.scan_status === "complete") {
      coverage.scan_status = "partial";
    }
    coverage.not_observed_means =
      coverage.scan_status === "complete"
        ? "no_candidate_in_files_reviewed"
        : "scope_was_truncated_or_partial";
  }
  coverage.candidate_dispositions = dispositions;
  coverage.candidate_disposition_counts = counts;
  return coverage;
}

/**
 * Finalize a metadata-only inventory without implying that file contents were
 * reviewed. Inventory never proves complete content coverage or an absent
 * candidate: scan_status is forced to partial/truncated and
 * `not_observed_means` states that contents were not reviewed.
 */
export function finalizeInventoryCoverage(
  coverage: CoverageReport,
  filesInventoried: readonly string[],
): CoverageReport {
  coverage.included_paths = [...new Set(filesInventoried)];
  coverage.files_reviewed = [];
  coverage.review_basis = "inventory_only";
  coverage.not_observed_means = "inventory_only_contents_not_reviewed";
  coverage.scan_status = coverage.truncation.truncated ? "truncated" : "partial";
  return coverage;
}

/** Open flags: prefer no-follow so the final path component cannot race into a symlink. */
function openReadFlags(): number {
  if (!("O_NOFOLLOW" in fsConstants)) {
    throw new Error("Filesystem traversal cannot be proven safe: O_NOFOLLOW is unavailable.");
  }
  const noFollow = (fsConstants as typeof fsConstants & { O_NOFOLLOW: number }).O_NOFOLLOW;
  // O_NONBLOCK keeps a raced FIFO/device from blocking the scanner's open().
  return fsConstants.O_RDONLY | noFollow | fsConstants.O_NONBLOCK;
}

/** Open flags for directory handles: no-follow, directory-only, non-blocking. */
function openDirFlags(): number {
  if (!("O_DIRECTORY" in fsConstants)) {
    throw new Error("Filesystem traversal cannot be proven safe: O_DIRECTORY is unavailable.");
  }
  return openReadFlags() | fsConstants.O_DIRECTORY;
}

interface OpenedCanonicalPath {
  handle: FileHandle;
  realPath: string;
  stat: Stats;
}

/**
 * Resolve a requested path once, then open every canonical component with
 * no-follow semantics. Node does not expose POSIX openat(2), so the nearest
 * safe primitive available here is component-wise opening plus post-open
 * descriptor identity checks. A raced component is either rejected by
 * O_NOFOLLOW or fails the opened-object containment/identity check before its
 * descriptor is used.
 */
async function openCanonicalPath(
  root: string,
  target: string,
  finalFlags: number,
  expectedFinal: "file" | "directory" | "any",
): Promise<OpenedCanonicalPath> {
  const relative = path.relative(root, target);
  if (relative === "" || relative.startsWith("..") || path.isAbsolute(relative)) {
    throw containmentError(target);
  }

  const components = relative.split(path.sep).filter(Boolean);
  let current = root;
  for (let index = 0; index < components.length; index++) {
    current = path.join(current, components[index]);
    const isFinal = index === components.length - 1;
    const handle = await fs.open(current, isFinal ? finalFlags : openDirFlags());
    try {
      const stat = await handle.stat();
      if (isFinal) {
        if (expectedFinal === "file" && !stat.isFile()) {
          throw new Error(`Not a regular file: "${target}".`);
        }
        if (expectedFinal === "directory" && !stat.isDirectory()) {
          throw new Error(`Not a directory: "${target}".`);
        }
      } else if (!stat.isDirectory()) {
        throw new Error(`Not a directory: "${current}".`);
      }

      // This validates the object returned by open(), not merely the path
      // that was checked before it. The identity comparison also detects a
      // component being replaced while it was being opened.
      const realPath = await verifyOpenedFileHandle(handle, current, root);
      if (isFinal) {
        return { handle, realPath, stat };
      }
      await handle.close();
    } catch (error) {
      await handle.close().catch(() => undefined);
      throw error;
    }
  }
  throw containmentError(target);
}

/** Resolve a requested path and reject a target that resolves outside root. */
async function resolveContainedPath(root: string, requested: string): Promise<string> {
  const lexical = path.isAbsolute(requested)
    ? resolveSafePath(root, path.relative(root, requested))
    : resolveSafePath(root, requested);
  const realPath = await fs.realpath(lexical);
  if (!isWithinRoot(root, realPath)) throw containmentError(requested);
  return realPath;
}

/** Do two stat results refer to the same filesystem object? */
export function sameFilesystemObject(
  a: Pick<Stats, "dev" | "ino">,
  b: Pick<Stats, "dev" | "ino">,
): boolean {
  return a.dev === b.dev && a.ino === b.ino;
}

/** Error marker codes used by containment verification. */
const CONTAINMENT_CODE = "SECURE_MCP_CONTAINMENT";
const PATH_CHANGED_CODE = "SECURE_MCP_PATH_CHANGED";

function containmentError(absPath: string): NodeJS.ErrnoException {
  const err = new Error(
    `Path escapes project root through a symlink: "${absPath}". Provide a file inside the project root.`,
  ) as NodeJS.ErrnoException;
  err.code = CONTAINMENT_CODE;
  return err;
}

function changedPathError(absPath: string): NodeJS.ErrnoException {
  const err = new Error(
    `Path changed while it was being opened and can no longer be proven inside the project root: "${absPath}".`,
  ) as NodeJS.ErrnoException;
  err.code = PATH_CHANGED_CODE;
  return err;
}

/**
 * Verify an already-opened file handle against the pathname it was opened from.
 *
 * The verification happens strictly AFTER `open`, and it validates the object
 * actually accessed: the current realpath must stay inside the root, and the
 * opened descriptor must still be the object the pathname currently names.
 * A concurrent intermediate-directory replacement either resolves outside the
 * root (containment failure) or makes the pathname name a different object than
 * the opened descriptor (identity failure). Either way the read is rejected.
 */
export async function verifyOpenedFileHandle(
  handle: FileHandle,
  absPath: string,
  realRoot: string,
): Promise<string> {
  const realFile = await fs.realpath(absPath);
  if (!isWithinRoot(realRoot, realFile)) throw containmentError(absPath);
  const current = await fs.lstat(absPath);
  const opened = await handle.stat();
  if (!sameFilesystemObject(opened, current)) throw changedPathError(absPath);
  return realFile;
}

/** Directory variant of {@link verifyOpenedFileHandle}. */
export async function verifyOpenedDirHandle(
  handle: FileHandle,
  dirPath: string,
  realRoot: string,
): Promise<string> {
  const realDir = await fs.realpath(dirPath);
  if (!isWithinRoot(realRoot, realDir)) throw containmentError(dirPath);
  const current = await fs.lstat(dirPath);
  const opened = await handle.stat();
  if (!sameFilesystemObject(opened, current)) throw changedPathError(dirPath);
  return realDir;
}

/**
 * Run a global regex over untrusted content with a bounded number of executions.
 *
 * Detector patterns must still use bounded spans; this is the outer per-detector
 * work budget so a pathological pattern cannot monopolize the scanner.
 */
export const MAX_REGEX_EXECS_PER_DETECTOR = 5_000;

export interface DetectorMatch {
  /** Full matched text. */
  match: string;
  /** 0-based index of the match in the scanned content. */
  index: number;
}

export function detectWithBudget(
  regex: RegExp,
  content: string,
  maxExecs: number = MAX_REGEX_EXECS_PER_DETECTOR,
): DetectorMatch[] {
  if (!regex.global) {
    throw new Error("detectWithBudget requires a global regex");
  }
  regex.lastIndex = 0;
  const matches: DetectorMatch[] = [];
  const budget = Number.isFinite(maxExecs) ? Math.max(0, Math.floor(maxExecs)) : 0;
  let execs = 0;
  while (execs < budget) {
    const match = regex.exec(content);
    if (match === null) break;
    execs++;
    matches.push({ match: match[0], index: match.index });
    // Prevent a future detector with a zero-width global match from spinning
    // forever. Existing detectors are non-empty, but this keeps the shared
    // engine fail-safe for any repository-controlled pattern added later.
    if (match[0].length === 0) regex.lastIndex++;
  }
  return matches;
}

/**
 * Read a file with a hard byte limit without buffering the whole file.
 * Opens without following the final path component when O_NOFOLLOW is available,
 * then verifies the OPENED object stays inside the project root before reading.
 * Containment is never proven from a mutable pathname checked before open.
 */
export async function readProjectFile(
  projectRoot: string,
  relativeOrAbsolute: string,
  maxBytes: number = DEFAULT_MAX_FILE_BYTES,
  allowedRoots?: readonly string[],
): Promise<ReadFileResult> {
  const root = await normalizeAuthorizedProjectRoot(projectRoot, allowedRoots);
  const realRoot = await fs.realpath(root);

  let handle: FileHandle | undefined;
  try {
    // Resolve an in-root symlink chain before opening. The canonical path is
    // then opened component by component with O_NOFOLLOW, so replacing an
    // intermediate directory with an external symlink cannot redirect the
    // descriptor outside the requested root.
    const realFile = await resolveContainedPath(realRoot, relativeOrAbsolute);
    const opened = await openCanonicalPath(realRoot, realFile, openReadFlags(), "file");
    handle = opened.handle;
    const st = opened.stat;

    const size = st.size;
    const requestedMaxBytes = Number.isFinite(maxBytes) ? Math.max(0, maxBytes) : 0;
    const safeMaxBytes = Math.min(requestedMaxBytes, HARD_MAX_FILE_BYTES);
    const toRead = Math.min(safeMaxBytes, size);
    const buf = Buffer.alloc(toRead);
    const { bytesRead } = await handle.read(buf, 0, toRead, 0);
    const content = buf.subarray(0, bytesRead).toString("utf8");
    return {
      relativePath: toPosix(path.relative(realRoot, realFile)),
      content,
      truncated: size > safeMaxBytes,
      size,
    };
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    // ELOOP / EMLINK often mean a symlink was encountered under O_NOFOLLOW.
    if (code === "ELOOP" || code === "EMLINK" || code === "EPERM") {
      throw new Error(
        `Path escapes project root through a symlink: "${relativeOrAbsolute}". Provide a file inside ${realRoot}.`,
      );
    }
    throw err;
  } finally {
    await handle?.close().catch(() => undefined);
  }
}

/** Read file if it exists; returns null when missing. */
export async function readProjectFileIfExists(
  projectRoot: string,
  relativePath: string,
  maxBytes?: number,
  allowedRoots?: readonly string[],
): Promise<ReadFileResult | null> {
  try {
    return await readProjectFile(projectRoot, relativePath, maxBytes, allowedRoots);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    // Path escape and other errors should propagate
    throw err;
  }
}

/** Stream top-level entries while retaining only a bounded preview. */
async function inspectTopLevel(
  projectRoot: string,
  maxEntries: number,
  allowedRoots?: readonly string[],
): Promise<TopLevelInspection> {
  const root = await normalizeAuthorizedProjectRoot(projectRoot, allowedRoots);
  // Bind enumeration to a verified root object: open the root, then confirm the
  // pathname still names that same directory after opendir finished.
  const rootHandle = await fs.open(root, openDirFlags());
  try {
    const before = await rootHandle.stat();
    const verifiedRoot = await verifyOpenedDirHandle(rootHandle, root, root);
    const directory = await fs.opendir(verifiedRoot);
    const entries: string[] = [];
    let entryCount = 0;
    let hasXcodeProject = false;
    let hasAndroidDirectory = false;
    let hasIosDirectory = false;
    let hasAppDirectory = false;
    let hasPagesDirectory = false;

    try {
      for await (const entry of directory) {
        entryCount++;
        const isDirectory = entry.isDirectory();
        if (entries.length < maxEntries) {
          entries.push(isDirectory ? `${entry.name}/` : entry.name);
        }
        if (!isDirectory) continue;
        hasXcodeProject ||= entry.name.endsWith(".xcodeproj") || entry.name.endsWith(".xcworkspace");
        hasAndroidDirectory ||= entry.name === "android";
        hasIosDirectory ||= entry.name === "ios";
        hasAppDirectory ||= entry.name === "app";
        hasPagesDirectory ||= entry.name === "pages";
      }
    } finally {
      await directory.close().catch(() => undefined);
    }

    // The root was replaced while it was being enumerated: the names above may
    // belong to a different directory and must not be trusted.
    const after = await fs.lstat(root);
    if (!sameFilesystemObject(before, after)) {
      throw new Error(`project_root changed during inspection: ${root}`);
    }

    entries.sort((a, b) => a.localeCompare(b));
    return {
      entries,
      truncated: entryCount > maxEntries,
      hasXcodeProject,
      hasAndroidDirectory,
      hasIosDirectory,
      hasAppDirectory,
      hasPagesDirectory,
    };
  } finally {
    await rootHandle.close().catch(() => undefined);
  }
}

/** List top-level directory names/files for architecture overview. */
export async function listTopLevel(projectRoot: string): Promise<string[]> {
  return (await inspectTopLevel(projectRoot, 1_000)).entries;
}

/** Signals used to decide whether a project really is an Expo / React Native app. */
export interface ExpoSignalInput {
  /** Merged dependency + devDependency names from package.json. */
  dependencyNames: string[];
  /** Raw app.json content when present. */
  appJsonContent?: string | null;
  /** Raw app.config.* content when present. */
  appConfigContent?: string | null;
  /** eas.json present at the project root. */
  hasEasConfig: boolean;
  /** metro.config.* present at the project root. */
  hasMetroConfig: boolean;
  /** react-native.config.* present at the project root. */
  hasReactNativeConfig: boolean;
  /** Both android/ and ios/ native project directories present. */
  hasNativeProjectDirs: boolean;
}

/**
 * Decide whether Expo / React Native guidance (expo-rn pack) applies.
 *
 * Deliberately narrow: a bare `app.json` (many tools use that name) or a stray
 * `react-native` dependency in a web/library package must not route a project to
 * the expo-rn pack. React Native without Expo still qualifies, but only with
 * corroborating app evidence (metro/RN config or native project dirs).
 */
export function looksLikeExpoOrReactNativeApp(input: ExpoSignalInput): boolean {
  const deps = new Set(input.dependencyNames);
  const hasExpoDependency =
    deps.has("expo") ||
    input.dependencyNames.some((d) => d.startsWith("expo-") || d.startsWith("@expo/"));
  if (hasExpoDependency || input.hasEasConfig) return true;

  // app.json only counts when it carries an Expo config block.
  if (input.appJsonContent && /"expo"\s*:\s*\{/.test(input.appJsonContent)) return true;
  // app.config.* only counts with a real Expo shape (type, import, or expo object).
  if (
    input.appConfigContent &&
    /\bExpoConfig\b|(?:from|import)\s+["']expo(?:\/[^"']*)?["']|["']expo["']\s*:|\bexpo\s*:\s*\{/.test(
      input.appConfigContent,
    )
  ) {
    return true;
  }

  const hasReactNativeDependency = deps.has("react-native");
  const hasAppEvidence =
    input.hasMetroConfig || input.hasReactNativeConfig || input.hasNativeProjectDirs;
  return hasReactNativeDependency && hasAppEvidence;
}

/** Lightweight project fingerprint used by tools. */
export async function profileProject(
  projectRoot: string,
  options: ProfileOptions = {},
): Promise<ProjectProfile> {
  const root = await normalizeAuthorizedProjectRoot(projectRoot, options.allowedRoots);
  const topLevel = await inspectTopLevel(
    root,
    Math.min(1_000, Math.max(20, options.maxFiles ?? 80)),
    options.allowedRoots,
  );
  const topLevelEntries = topLevel.entries;
  const focusPrefixes = options.focusPrefixes;
  const metadataReadLimit = (defaultLimit: number): number =>
    options.maxFileBytes ?? defaultLimit;

  const exists = async (rel: string): Promise<boolean> => {
    try {
      const authorizedRoot = await normalizeAuthorizedProjectRoot(root, options.allowedRoots);
      const target = await resolveContainedPath(authorizedRoot, rel);
      const opened = await openCanonicalPath(authorizedRoot, target, openReadFlags(), "any");
      await opened.handle.close();
      return true;
    } catch {
      return false;
    }
  };

  const hasPackageJson = await exists("package.json");
  const hasTsConfig = (await exists("tsconfig.json")) || (await exists("jsconfig.json"));
  const hasNextConfig =
    (await exists("next.config.js")) ||
    (await exists("next.config.mjs")) ||
    (await exists("next.config.ts")) ||
    (await exists("next.config.cjs"));
  const hasPackageSwift = await exists("Package.swift");
  const hasXcodeProject = topLevel.hasXcodeProject;

  // Sample walk for language presence (cheap caps); honor focus_paths when set.
  const { files } = await walkProject(root, {
    maxFiles: options.maxFiles ?? 80,
    maxDepth: options.maxDepth ?? 6,
    maxFileBytes: options.maxFileBytes,
    maxTotalBytes: options.maxTotalBytes,
    allowedRoots: options.allowedRoots,
    extensions: new Set([".ts", ".tsx", ".js", ".jsx", ".swift", ".json", ".pbxproj", ".plist"]),
    focusPrefixes,
  });
  const hasSwiftFiles = files.some((f) => f.ext === ".swift") || hasPackageSwift || hasXcodeProject;
  const hasTypeScriptFiles =
    files.some((f) => f.ext === ".ts" || f.ext === ".tsx") || hasTsConfig || hasPackageJson;

  let dependencyNames: string[] = [];
  if (hasPackageJson) {
    const pkgFile = await readProjectFileIfExists(
      root,
      "package.json",
      metadataReadLimit(64 * 1024),
      options.allowedRoots,
    );
    if (pkgFile) {
      try {
        const pkg = JSON.parse(pkgFile.content) as {
          dependencies?: Record<string, string>;
          devDependencies?: Record<string, string>;
        };
        dependencyNames = [
          ...Object.keys(pkg.dependencies ?? {}),
          ...Object.keys(pkg.devDependencies ?? {}),
        ];
      } catch {
        // ignore invalid package.json
      }
    }
  }

  const appJson = await readProjectFileIfExists(
    root,
    "app.json",
    metadataReadLimit(32 * 1024),
    options.allowedRoots,
  );
  let appConfigContent: string | null = null;
  for (const name of ["app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs"]) {
    const file = await readProjectFileIfExists(
      root,
      name,
      metadataReadLimit(32 * 1024),
      options.allowedRoots,
    );
    if (file) {
      appConfigContent = file.content;
      break;
    }
  }

  const hasExpo = looksLikeExpoOrReactNativeApp({
    dependencyNames,
    appJsonContent: appJson?.content ?? null,
    appConfigContent,
    hasEasConfig: await exists("eas.json"),
    hasMetroConfig:
      (await exists("metro.config.js")) ||
      (await exists("metro.config.cjs")) ||
      (await exists("metro.config.ts")),
    hasReactNativeConfig:
      (await exists("react-native.config.js")) || (await exists("react-native.config.ts")),
    hasNativeProjectDirs:
      topLevel.hasAndroidDirectory && topLevel.hasIosDirectory,
  });

  // Conservative macOS detection: AppKit / Mac Catalyst / macosx deployment signals
  let hasMacOS = false;
  if (hasSwiftFiles) {
    const sampleSwift = files.filter((f) => f.ext === ".swift").slice(0, 30);
    for (const f of sampleSwift) {
      const body = await readProjectFileIfExists(
        root,
        f.relativePath,
        metadataReadLimit(32 * 1024),
        options.allowedRoots,
      );
      if (!body) continue;
      if (
        /\bimport\s+AppKit\b|\bNSApplication\b|\bNSWindow\b|\bMacCatalyst\b|#if\s+os\(macOS\)/.test(
          body.content,
        )
      ) {
        hasMacOS = true;
        break;
      }
    }
    if (!hasMacOS) {
      const pbx = files.find((f) => f.relativePath.endsWith(".pbxproj"));
      if (pbx) {
        const body = await readProjectFileIfExists(
          root,
          pbx.relativePath,
          metadataReadLimit(64 * 1024),
          options.allowedRoots,
        );
        if (body && /SDKROOT\s*=\s*macosx|MACOSX_DEPLOYMENT_TARGET/.test(body.content)) {
          hasMacOS = true;
        }
      }
    }
  }

  const likelyStacks: StackFocus[] = ["common"];
  if (hasTypeScriptFiles) likelyStacks.push("typescript");
  // Prefer explicit Next config; avoid labeling pure Expo app/ as nextjs
  if (hasNextConfig) {
    likelyStacks.push("nextjs");
  } else if (
    !hasExpo &&
    (topLevel.hasAppDirectory || topLevel.hasPagesDirectory)
  ) {
    likelyStacks.push("nextjs");
  }
  if (hasExpo) likelyStacks.push("expo");
  if (hasSwiftFiles) likelyStacks.push("swift");

  return {
    root,
    hasPackageJson,
    hasNextConfig,
    hasTsConfig,
    hasPackageSwift,
    hasXcodeProject,
    hasSwiftFiles,
    hasTypeScriptFiles,
    hasExpo,
    hasMacOS,
    likelyStacks,
    topLevelEntries,
    topLevelEntriesTruncated: topLevel.truncated,
  };
}

/**
 * Ensure tool text responses stay within a character budget for agent context.
 */
export function truncateText(
  text: string,
  limit: number = CHARACTER_LIMIT,
): { text: string; truncated: boolean } {
  if (text.length <= limit) {
    return { text, truncated: false };
  }
  const msg =
    `\n\n…[truncated: response was ${text.length} chars; limit is ${limit}. ` +
    `Narrow the project_root, lower max_files, or request a more focused tool.]\n`;
  return {
    text: text.slice(0, Math.max(0, limit - msg.length)) + msg,
    truncated: true,
  };
}

/** Build a standard MCP tool error payload. */
export function toolError(
  error: unknown,
  hint?: string,
): {
  content: { type: "text"; text: string }[];
  isError: true;
  structuredContent: { ok: false; error: string; hint?: string };
} {
  // Error text can embed caller-controlled values (paths, snippets); route it
  // through the same secret policy so fallback/error responses stay safe.
  const message = truncateText(
    redactedEvidence(error instanceof Error ? error.message : String(error)),
    4_000,
  ).text;
  const safeHint = hint ? truncateText(redactedEvidence(hint), 2_000).text : undefined;
  const base = {
    ok: false as const,
    error: message,
    ...(safeHint ? { hint: safeHint } : {}),
    output_trust: "untrusted" as const,
    output_notice: UNTRUSTED_OUTPUT_NOTICE,
  };
  const bounded = boundStructuredPayload(base).data as {
    ok: false;
    error: string;
    hint?: string;
  };
  const text = bounded.hint
    ? `${UNTRUSTED_OUTPUT_NOTICE}\n\nError: ${bounded.error}\n\nHint: ${bounded.hint}`
    : `${UNTRUSTED_OUTPUT_NOTICE}\n\nError: ${bounded.error}`;
  return {
    isError: true,
    content: [{ type: "text", text }],
    structuredContent: bounded,
  };
}

/** Keys of large arrays we may shrink so structured MCP payloads stay bounded. */
const SHRINKABLE_ARRAY_KEYS = [
  "findings",
  "items",
  "files_reviewed",
  "included_paths",
  "sample_files",
  "threats",
  "finding_seeds",
] as const;

/** Nested coverage arrays that can dominate structuredContent size. */
const COVERAGE_SHRINKABLE_ARRAY_KEYS = [
  "included_paths",
  "excluded_paths",
  "ignored_paths",
  "candidate_dispositions",
  "files_reviewed",
] as const;

function halfArrayIfLarge(value: unknown): { value: unknown; shrunk: boolean } {
  if (Array.isArray(value) && value.length > 1) {
    return { value: value.slice(0, Math.max(1, Math.floor(value.length / 2))), shrunk: true };
  }
  return { value, shrunk: false };
}

function shrinkCoverageArrays(coverage: unknown): { coverage: unknown; shrunk: boolean } {
  if (!coverage || typeof coverage !== "object") {
    return { coverage, shrunk: false };
  }
  const next: Record<string, unknown> = { ...(coverage as Record<string, unknown>) };
  let shrunk = false;
  for (const key of COVERAGE_SHRINKABLE_ARRAY_KEYS) {
    const result = halfArrayIfLarge(next[key]);
    if (result.shrunk) {
      next[key] = result.value;
      shrunk = true;
    }
  }
  return { coverage: next, shrunk };
}

/** Minimal coverage stub for last-resort envelopes — never re-attaches bulk path lists. */
function hardCappedCoverageStub(coverage: CoverageReport | undefined): CoverageReport | undefined {
  if (!coverage) return undefined;
  return {
    included_paths: [],
    excluded_paths: [],
    ignored_paths: [],
    caps: coverage.caps,
    truncation: {
      truncated: true,
      reasons: [...new Set([...coverage.truncation.reasons, "response_size"])],
      coverage_events_truncated: coverage.truncation.coverage_events_truncated,
    },
    files_reviewed: [],
    candidate_dispositions: [],
    candidate_disposition_counts: coverage.candidate_disposition_counts,
    ...(coverage.review_basis ? { review_basis: coverage.review_basis } : {}),
    scan_status: "truncated",
    not_observed_means: "scope_was_truncated_or_partial",
  };
}

function markResponseSizeTruncation<T extends object>(data: T): T & { truncated: boolean } {
  const coverage = (data as { coverage?: CoverageReport }).coverage;
  return {
    ...data,
    truncated: true,
    ...(coverage
      ? {
          coverage: {
            ...coverage,
            truncation: {
              ...coverage.truncation,
              truncated: true,
              reasons: [...new Set([...coverage.truncation.reasons, "response_size"])],
            },
            scan_status: "truncated" as const,
            not_observed_means: "scope_was_truncated_or_partial" as const,
          },
        }
      : {}),
  } as T & { truncated: boolean };
}

/** Bounded fragments for the last-resort envelope. */
const MAX_ENVELOPE_PROJECT_ROOT_CHARS = 200;
const MAX_ENVELOPE_SUMMARY_CHARS = 600;
const ENVELOPE_TRUNCATION_MARKER = "…[truncated]";

/** Deterministic truncation that keeps the result at or under the budget. */
function truncateToBudget(text: string, budget: number): string {
  if (text.length <= budget) return text;
  if (budget <= ENVELOPE_TRUNCATION_MARKER.length) return text.slice(0, budget);
  return `${text.slice(0, budget - ENVELOPE_TRUNCATION_MARKER.length)}${ENVELOPE_TRUNCATION_MARKER}`;
}

/**
 * Shrink large array fields until JSON stays under the character budget.
 * Ensures structuredContent is bounded, not only the text channel.
 */
export function boundStructuredPayload<T extends object>(
  data: T,
  limit: number = CHARACTER_LIMIT,
): { data: T; truncated: boolean } {
  let current: object = data;
  let truncated = false;
  let encoded = JSON.stringify(current);
  if (encoded.length <= limit) {
    return { data, truncated: false };
  }

  truncated = true;
  current = markResponseSizeTruncation(current as T);

  // Progressively cut shrinkable arrays (halve each pass), including nested coverage.
  for (let pass = 0; pass < 8; pass++) {
    encoded = JSON.stringify(current);
    if (encoded.length <= limit) break;
    const next: Record<string, unknown> = { ...(current as Record<string, unknown>) };
    let shrunk = false;
    for (const key of SHRINKABLE_ARRAY_KEYS) {
      const result = halfArrayIfLarge(next[key]);
      if (result.shrunk) {
        next[key] = result.value;
        shrunk = true;
      }
    }
    const coverageResult = shrinkCoverageArrays(next.coverage);
    if (coverageResult.shrunk) {
      next.coverage = coverageResult.coverage;
      shrunk = true;
    }
    if (!shrunk) break;
    current = next;
  }

  encoded = JSON.stringify(current);
  if (encoded.length > limit) {
    // Last resort: keep a summary envelope only. Every caller-controlled field
    // (project_root, summary) is redacted and truncated up front so the
    // envelope cannot stay oversized no matter what the caller supplied.
    const base = current as Record<string, unknown>;
    const coverageStub = hardCappedCoverageStub(
      (base.coverage as CoverageReport | undefined) ?? undefined,
    );
    let envelope: Record<string, unknown> = markResponseSizeTruncation({
      ok: base.ok ?? true,
      project_root:
        typeof base.project_root === "string"
          ? redactedEvidence(truncateToBudget(base.project_root, MAX_ENVELOPE_PROJECT_ROOT_CHARS))
          : (base.project_root ?? null),
      summary:
        typeof base.summary === "string"
          ? truncateToBudget(base.summary, MAX_ENVELOPE_SUMMARY_CHARS)
          : "Response truncated to stay within the MCP character budget.",
      truncated: true,
      notes: [
        "structuredContent was reduced because the full payload exceeded CHARACTER_LIMIT.",
        "Narrow project_root, lower max_files, or request a more focused tool.",
      ],
      ...(coverageStub ? { coverage: coverageStub } : {}),
    });

    // Final serialized-size assertion: drop pieces until the envelope is
    // guaranteed to fit, so no caller-controlled field can keep it oversized.
    let encodedEnvelope = JSON.stringify(envelope);
    while (encodedEnvelope.length > limit) {
      if (envelope.coverage !== undefined) {
        const { coverage: _drop, ...rest } = envelope;
        envelope = rest;
      } else if (envelope.notes !== undefined) {
        const { notes: _drop, ...rest } = envelope;
        envelope = rest;
      } else if (envelope.project_root !== null && envelope.project_root !== undefined) {
        envelope = { ...envelope, project_root: null };
      } else {
        envelope = { ...envelope, summary: "" };
      }
      encodedEnvelope = JSON.stringify(envelope);
    }
    current = envelope;
  }

  return { data: current as T, truncated };
}

/** Build a standard MCP tool success payload with JSON text + structuredContent. */
export function toolSuccess<T extends object>(
  data: T,
  options: { markdown?: string; responseFormat?: "json" | "markdown" } = {},
): {
  content: { type: "text"; text: string }[];
  structuredContent: T;
} {
  // Keep this as the final output boundary as well as the finding-specific
  // redaction callers. Static tools add caller/repository strings in more than
  // one place, and a new caller must not be able to bypass the central policy.
  const safeData = redactValue({
    ...data,
    output_trust: "untrusted" as const,
    output_notice: UNTRUSTED_OUTPUT_NOTICE,
  }) as T;
  const contentPrefix = `${UNTRUSTED_OUTPUT_NOTICE}\n\n`;
  const contentBudget = Math.max(1, CHARACTER_LIMIT - contentPrefix.length);
  const boundedResult = boundStructuredPayload(safeData, contentBudget);
  let structured = boundedResult.data;
  const structuredTruncated = boundedResult.truncated;
  const format = options.responseFormat ?? "json";
  const safeMarkdown = options.markdown ? redactedEvidence(options.markdown) : undefined;

  const renderMarkdown =
    format === "markdown" &&
    safeMarkdown !== undefined &&
    !structuredTruncated &&
    safeMarkdown.length <= contentBudget;

  if (
    format === "markdown" &&
    safeMarkdown !== undefined &&
    !renderMarkdown &&
    !structuredTruncated
  ) {
    // The requested Markdown representation exceeded the response budget even
    // though its structured source did not. Preserve a complete JSON fallback
    // and mark the representation change instead of slicing Markdown mid-field.
    structured = boundStructuredPayload(
      markResponseSizeTruncation(structured),
      contentBudget,
    ).data as T;
  }

  let body = renderMarkdown ? safeMarkdown : JSON.stringify(structured, null, 2);
  if (body.length > contentBudget) {
    // Pretty-print whitespace can push an otherwise bounded JSON value over the
    // text-channel limit. Compact serialization stays parseable and represents
    // the same structuredContent without losing fields mid-token.
    body = JSON.stringify(structured);
  }

  if (body.length > contentBudget) {
    // Defensive backstop if a future serializer changes the size calculation.
    structured = boundStructuredPayload(
      markResponseSizeTruncation(structured),
      contentBudget,
    ).data as T;
    body = JSON.stringify(structured);
  }

  return {
    content: [{ type: "text", text: `${contentPrefix}${body}` }],
    structuredContent: structured as T,
  };
}

/** Simple line finder for evidence (1-based). */
export function findLineNumber(content: string, matchIndex: number): number {
  if (matchIndex <= 0) return 1;
  let line = 1;
  for (let i = 0; i < matchIndex && i < content.length; i++) {
    if (content[i] === "\n") line++;
  }
  return line;
}

/** Extract a short evidence snippet around a match. */
export function snippetAround(content: string, index: number, radius = 80): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  let snip = content.slice(start, end).replace(/\s+/g, " ").trim();
  if (start > 0) snip = "…" + snip;
  if (end < content.length) snip = snip + "…";
  // Snippets are untrusted source context. Redact at construction time so a
  // future detector caller cannot accidentally bypass the finding serializer.
  return redactedEvidence(snip);
}
