/**
 * Shared category-tool scan boundary.
 *
 * Composes filesystem policy (authorize root, profile, bounded walk, read)
 * without reimplementing path safety. Tools supply file selection and
 * per-file detectors; coverage receipts stay on the walk session.
 */

import type { ServerConfig } from "../config.js";
import {
  normalizeAuthorizedProjectRoot,
  profileProject,
  readProjectFile,
  walkProject,
  type CoverageCandidate,
  type CoverageSession,
  type FileEntry,
} from "./filesystem.js";
import type { CoverageReport, ProjectProfile } from "./types.js";

export type ProjectScanSkip = { skip: false } | { skip: true; reason: string };

export interface ProjectScanContext {
  root: string;
  profile?: ProjectProfile;
  coverageSession: CoverageSession;
  files: FileEntry[];
}

export interface ProjectScanOptions {
  projectRoot: string;
  config: ServerConfig;
  maxFiles?: number;
  focusPaths?: string[];
  extensions?: Set<string> | null;
  /** When true, profile the root before walking. Default true. */
  profile?: boolean;
  selectFile?: (file: FileEntry, ctx: ProjectScanContext) => ProjectScanSkip;
  onFile?: (file: FileEntry, content: string, ctx: ProjectScanContext) => void | Promise<void>;
}

export interface ProjectScanResult {
  root: string;
  profile?: ProjectProfile;
  files: FileEntry[];
  filesReviewed: string[];
  coverageSession: CoverageSession;
  finishCoverage: (candidates?: ReadonlyArray<CoverageCandidate>) => CoverageReport;
}

export async function runProjectScan(options: ProjectScanOptions): Promise<ProjectScanResult> {
  const { config } = options;
  const root = await normalizeAuthorizedProjectRoot(options.projectRoot, config.allowedRoots);
  const effectiveMaxFiles = options.maxFiles ?? config.defaultMaxFiles;
  const walkLimits = {
    maxFiles: effectiveMaxFiles,
    maxDepth: config.maxDepth,
    maxFileBytes: config.maxFileBytes,
    maxTotalBytes: config.maxTotalBytes,
    allowedRoots: config.allowedRoots,
    focusPrefixes: options.focusPaths,
  };

  const profile =
    options.profile === false
      ? undefined
      : await profileProject(root, walkLimits);

  const { files, coverageSession } = await walkProject(root, {
    ...walkLimits,
    ...(options.extensions !== undefined ? { extensions: options.extensions } : {}),
  });

  const ctx: ProjectScanContext = { root, profile, coverageSession, files };
  const filesReviewed: string[] = [];

  for (const file of files) {
    if (file.size > config.maxFileBytes) {
      coverageSession.recordExclusion({
        path: file.relativePath,
        kind: "file",
        reason: "max_file_bytes",
      });
      continue;
    }

    const selection = options.selectFile?.(file, ctx) ?? { skip: false };
    if (selection.skip) {
      coverageSession.recordExclusion({
        path: file.relativePath,
        kind: "file",
        reason: selection.reason,
      });
      continue;
    }

    let content: string;
    try {
      content = (
        await readProjectFile(
          root,
          file.relativePath,
          config.maxFileBytes,
          config.allowedRoots,
        )
      ).content;
    } catch {
      coverageSession.recordExclusion({
        path: file.relativePath,
        kind: "file",
        reason: "file_read_error",
      });
      continue;
    }

    filesReviewed.push(file.relativePath);
    coverageSession.recordReviewedFile(file.relativePath);
    await options.onFile?.(file, content, ctx);
  }

  return {
    root,
    profile,
    files,
    filesReviewed,
    coverageSession,
    finishCoverage: (candidates) => coverageSession.finish(candidates),
  };
}
