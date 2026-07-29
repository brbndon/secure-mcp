/**
 * Conservative filesystem helpers for local code audits.
 *
 * Design goals:
 * - Never escape the requested project root
 * - Never execute user code
 * - Cap file size, tree depth, and total files to keep agents usable on large repos
 */

import { constants as fsConstants, promises as fs } from "node:fs";
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
  /** Cap on coverage path events retained in the report (default 1000). */
  maxCoverageEvents?: number;
}

export interface ProfileOptions {
  /** When set, language sampling walks only these relative prefixes. */
  focusPrefixes?: string[];
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
  let stat;
  try {
    stat = await fs.stat(absolute);
  } catch {
    throw new Error(
      `project_root does not exist: ${absolute}. Check the path and that the MCP process can access it.`,
    );
  }
  if (!stat.isDirectory()) {
    throw new Error(`project_root is not a directory: ${absolute}`);
  }
  // Use the real root for every later containment comparison.
  return await fs.realpath(absolute);
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
  const root = await normalizeProjectRoot(projectRoot);
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const maxFileBytes = options.maxFileBytes ?? DEFAULT_MAX_FILE_BYTES;
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

  async function walk(dir: string, depth: number): Promise<void> {
    if (truncated) return;
    if (depth > maxDepth) return;

    try {
      const realDir = await fs.realpath(dir);
      if (!isWithinRoot(root, realDir)) {
        truncationReasons.add("symlink_containment");
        addEvent(excludedPaths, {
          path: toPosix(path.relative(root, dir)) || ".",
          kind: "directory",
          reason: "symlink_target_outside_root",
        });
        return;
      }
    } catch {
      addEvent(excludedPaths, {
        path: toPosix(path.relative(root, dir)) || ".",
        kind: "directory",
        reason: "directory_realpath_error",
      });
      return;
    }

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      addEvent(excludedPaths, {
        path: toPosix(path.relative(root, dir)) || ".",
        kind: "directory",
        reason: "directory_read_error",
      });
      return;
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
        try {
          const realDirectory = await fs.realpath(abs);
          if (!isWithinRoot(root, realDirectory)) {
            truncationReasons.add("symlink_containment");
            addEvent(excludedPaths, {
              path: rel,
              kind: "directory",
              reason: "symlink_target_outside_root",
            });
            continue;
          }
        } catch {
          addEvent(excludedPaths, { path: rel, kind: "directory", reason: "directory_realpath_error" });
          continue;
        }
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

      // lstat avoids following a raced symlink between readdir and size check.
      let size = 0;
      try {
        const st = await fs.lstat(abs);
        if (st.isSymbolicLink()) {
          addEvent(excludedPaths, {
            path: rel,
            kind: "symlink",
            reason: "symlink_not_followed",
          });
          continue;
        }
        if (!st.isFile()) {
          addEvent(excludedPaths, { path: rel, kind: "other", reason: "not_a_regular_file" });
          continue;
        }
        const realFile = await fs.realpath(abs);
        if (!isWithinRoot(root, realFile)) {
          truncationReasons.add("symlink_containment");
          addEvent(excludedPaths, {
            path: rel,
            kind: "file",
            reason: "symlink_target_outside_root",
          });
          continue;
        }
        size = st.size;
      } catch (error) {
        const code = (error as NodeJS.ErrnoException).code;
        addEvent(excludedPaths, {
          path: rel,
          kind: "file",
          reason: code === "ELOOP" ? "symlink_unresolvable" : "file_stat_error",
        });
        continue;
      }

      if (size > maxFileBytes) {
        truncationReasons.add("max_file_bytes");
        addEvent(excludedPaths, { path: rel, kind: "file", reason: "max_file_bytes" });
        continue;
      }

      files.push({ absolutePath: abs, relativePath: rel, size, ext });
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
  const walkTruncated = truncated || truncationReasons.has("max_files") || truncationReasons.has("max_depth") || truncationReasons.has("max_file_bytes") || truncationReasons.has("symlink_containment") || truncationReasons.has("response_size");
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
      caps: { max_files: maxFiles, max_depth: maxDepth, max_file_bytes: maxFileBytes },
      truncation: {
        truncated: effectiveTruncated || coverageEventsTruncated,
        reasons: [...truncationReasons],
        coverage_events_truncated: coverageEventsTruncated,
      },
      files_reviewed: [],
      candidate_dispositions: [],
      candidate_disposition_counts: candidateDispositionCounts,
      scan_status,
      not_observed_means:
        scan_status === "complete"
          ? "no_candidate_in_files_reviewed"
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
  coverage.files_reviewed = [...new Set(filesReviewed)];
  coverage.candidate_dispositions = dispositions;
  coverage.candidate_disposition_counts = counts;
  return coverage;
}

/** Finalize a metadata-only inventory without implying that file contents were reviewed. */
export function finalizeInventoryCoverage(
  coverage: CoverageReport,
  filesInventoried: readonly string[],
): CoverageReport {
  coverage.files_reviewed = [];
  coverage.not_observed_means =
    coverage.truncation.truncated || coverage.truncation.reasons.length > 0
      ? "scope_was_truncated_or_partial"
      : "no_candidate_in_files_reviewed";
  coverage.scan_status = coverage.truncation.truncated
    ? "truncated"
    : coverage.excluded_paths.length > 0 || coverage.ignored_paths.length > 0
      ? "partial"
      : "complete";
  coverage.not_observed_means =
    coverage.scan_status === "complete"
      ? "no_candidate_in_files_reviewed"
      : "scope_was_truncated_or_partial";
  coverage.included_paths = [...new Set(filesInventoried)];
  return coverage;
}

/** Open flags: prefer no-follow so the final path component cannot race into a symlink. */
function openReadFlags(): number {
  const noFollow =
    "O_NOFOLLOW" in fsConstants
      ? (fsConstants as typeof fsConstants & { O_NOFOLLOW: number }).O_NOFOLLOW
      : 0;
  return fsConstants.O_RDONLY | noFollow;
}

/**
 * Read a file with a hard byte limit without buffering the whole file.
 * Opens without following the final path component when O_NOFOLLOW is available,
 * then verifies the opened path remains inside the project root.
 */
export async function readProjectFile(
  projectRoot: string,
  relativeOrAbsolute: string,
  maxBytes: number = DEFAULT_MAX_FILE_BYTES,
): Promise<ReadFileResult> {
  const root = await normalizeProjectRoot(projectRoot);
  const abs = path.isAbsolute(relativeOrAbsolute)
    ? resolveSafePath(root, path.relative(root, relativeOrAbsolute))
    : resolveSafePath(root, relativeOrAbsolute);

  const realRoot = await fs.realpath(root);

  // Reject final-component symlinks even when O_NOFOLLOW is unavailable.
  let lstat;
  try {
    lstat = await fs.lstat(abs);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") throw err;
    throw err;
  }
  if (lstat.isSymbolicLink()) {
    throw new Error(
      `Path escapes project root through a symlink: "${relativeOrAbsolute}". Provide a file inside ${realRoot}.`,
    );
  }
  if (!lstat.isFile()) {
    throw new Error(`Not a regular file: "${relativeOrAbsolute}".`);
  }

  let handle: FileHandle | undefined;
  try {
    handle = await fs.open(abs, openReadFlags());
    const st = await handle.stat();
    if (!st.isFile()) {
      throw new Error(`Not a regular file: "${relativeOrAbsolute}".`);
    }

    // Verify the opened path (and any intermediate resolution) stays in-root.
    const realFile = await fs.realpath(abs);
    if (!isWithinRoot(realRoot, realFile)) {
      throw new Error(
        `Path escapes project root through a symlink: "${relativeOrAbsolute}". Provide a file inside ${realRoot}.`,
      );
    }

    const size = st.size;
    const toRead = Math.min(maxBytes, size);
    const buf = Buffer.alloc(toRead);
    const { bytesRead } = await handle.read(buf, 0, toRead, 0);
    const content = buf.subarray(0, bytesRead).toString("utf8");
    return {
      relativePath: toPosix(path.relative(realRoot, realFile)),
      content,
      truncated: size > maxBytes,
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
): Promise<ReadFileResult | null> {
  try {
    return await readProjectFile(projectRoot, relativePath, maxBytes);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === "ENOENT") return null;
    // Path escape and other errors should propagate
    throw err;
  }
}

/** List top-level directory names/files for architecture overview. */
export async function listTopLevel(projectRoot: string): Promise<string[]> {
  const root = await normalizeProjectRoot(projectRoot);
  const entries = await fs.readdir(root, { withFileTypes: true });
  return entries
    .map((e) => (e.isDirectory() ? `${e.name}/` : e.name))
    .sort((a, b) => a.localeCompare(b));
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
  const root = await normalizeProjectRoot(projectRoot);
  const topLevelEntries = await listTopLevel(root);
  const focusPrefixes = options.focusPrefixes;

  const exists = async (rel: string): Promise<boolean> => {
    try {
      await fs.access(path.join(root, rel));
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
  const hasXcodeProject =
    topLevelEntries.some((e) => e.endsWith(".xcodeproj/")) ||
    topLevelEntries.some((e) => e.endsWith(".xcworkspace/"));

  // Sample walk for language presence (cheap caps); honor focus_paths when set.
  const { files } = await walkProject(root, {
    maxFiles: 80,
    maxDepth: 6,
    extensions: new Set([".ts", ".tsx", ".js", ".jsx", ".swift", ".json", ".pbxproj", ".plist"]),
    focusPrefixes,
  });
  const hasSwiftFiles = files.some((f) => f.ext === ".swift") || hasPackageSwift || hasXcodeProject;
  const hasTypeScriptFiles =
    files.some((f) => f.ext === ".ts" || f.ext === ".tsx") || hasTsConfig || hasPackageJson;

  let dependencyNames: string[] = [];
  if (hasPackageJson) {
    const pkgFile = await readProjectFileIfExists(root, "package.json", 64 * 1024);
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

  const appJson = await readProjectFileIfExists(root, "app.json", 32 * 1024);
  let appConfigContent: string | null = null;
  for (const name of ["app.config.js", "app.config.ts", "app.config.mjs", "app.config.cjs"]) {
    const file = await readProjectFileIfExists(root, name, 32 * 1024);
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
      topLevelEntries.includes("android/") && topLevelEntries.includes("ios/"),
  });

  // Conservative macOS detection: AppKit / Mac Catalyst / macosx deployment signals
  let hasMacOS = false;
  if (hasSwiftFiles) {
    const sampleSwift = files.filter((f) => f.ext === ".swift").slice(0, 30);
    for (const f of sampleSwift) {
      const body = await readProjectFileIfExists(root, f.relativePath, 32 * 1024);
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
        const body = await readProjectFileIfExists(root, pbx.relativePath, 64 * 1024);
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
    (topLevelEntries.includes("app/") || topLevelEntries.includes("pages/"))
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
  const message = error instanceof Error ? error.message : String(error);
  const text = hint ? `Error: ${message}\n\nHint: ${hint}` : `Error: ${message}`;
  return {
    isError: true,
    content: [{ type: "text", text }],
    structuredContent: {
      ok: false,
      error: message,
      ...(hint ? { hint } : {}),
    },
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
    // Last resort: keep summary envelope only; hard-cap or drop bulk coverage.
    const base = current as Record<string, unknown>;
    const coverageStub = hardCappedCoverageStub(
      (base.coverage as CoverageReport | undefined) ?? undefined,
    );
    let envelope: Record<string, unknown> = markResponseSizeTruncation({
      ok: base.ok ?? true,
      project_root: base.project_root ?? null,
      summary:
        typeof base.summary === "string"
          ? base.summary
          : "Response truncated to stay within the MCP character budget.",
      truncated: true,
      notes: [
        "structuredContent was reduced because the full payload exceeded CHARACTER_LIMIT.",
        "Narrow project_root, lower max_files, or request a more focused tool.",
      ],
      ...(coverageStub ? { coverage: coverageStub } : {}),
    });
    if (JSON.stringify(envelope).length > limit) {
      // Drop coverage entirely if the stub still exceeds the budget.
      const { coverage: _drop, ...withoutCoverage } = envelope;
      envelope = withoutCoverage;
    }
    if (JSON.stringify(envelope).length > limit && typeof envelope.summary === "string") {
      // Trim summary as a final squeeze so JSON stays at or under the limit.
      const overhead = JSON.stringify({ ...envelope, summary: "" }).length;
      const maxSummary = Math.max(0, limit - overhead - 2);
      envelope = { ...envelope, summary: envelope.summary.slice(0, maxSummary) };
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
  const { data: bounded, truncated: structuredTruncated } = boundStructuredPayload(data);
  const format = options.responseFormat ?? "json";
  let text: string;
  if (format === "markdown" && options.markdown && !structuredTruncated) {
    text = options.markdown;
  } else if (format === "markdown" && options.markdown && structuredTruncated) {
    // Re-serialize from bounded structured data so markdown cannot reintroduce bulk.
    text = JSON.stringify(bounded, null, 2);
  } else {
    text = JSON.stringify(bounded, null, 2);
  }
  const { text: limited, truncated: textTruncated } = truncateText(text);
  const structured =
    structuredTruncated || textTruncated
      ? markResponseSizeTruncation(bounded)
      : bounded;
  return {
    content: [{ type: "text", text: limited }],
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
  return snip;
}
