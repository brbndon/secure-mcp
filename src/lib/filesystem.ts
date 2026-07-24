/**
 * Conservative filesystem helpers for local code audits.
 *
 * Design goals:
 * - Never escape the requested project root
 * - Never execute user code
 * - Cap file size, tree depth, and total files to keep agents usable on large repos
 */

import { promises as fs } from "node:fs";
import path from "node:path";
import type { ProjectProfile, StackFocus } from "./types.js";

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
  return absolute;
}

function toPosix(p: string): string {
  return p.split(path.sep).join("/");
}

function shouldIgnoreName(
  name: string,
  isDir: boolean,
  ignoreDirs: Set<string>,
  ignoreFiles: Set<string>,
): boolean {
  if (name.startsWith(".") && name !== ".env" && name !== ".env.example" && name !== ".env.local") {
    // Keep security-relevant env files; skip other dotfiles/dirs by default.
    if (isDir || !name.startsWith(".env")) {
      // Allow .github for workflow review if needed — skip most dot dirs.
      if (name !== ".github" && name !== ".env") {
        if (isDir) return true;
      }
    }
  }
  if (isDir && ignoreDirs.has(name)) return true;
  if (!isDir && ignoreFiles.has(name)) return true;
  return false;
}

/**
 * Depth-first walk of a project tree with safety caps.
 * Returns files only (not directories).
 */
export async function walkProject(
  projectRoot: string,
  options: WalkOptions = {},
): Promise<{ files: FileEntry[]; truncated: boolean }> {
  const root = await normalizeProjectRoot(projectRoot);
  const maxFiles = options.maxFiles ?? DEFAULT_MAX_FILES;
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DEPTH;
  const extensions = options.extensions === undefined ? CODE_EXTENSIONS : options.extensions;
  const ignoreDirs = options.ignoreDirs ?? DEFAULT_IGNORE_DIRS;
  const ignoreFiles = options.ignoreFiles ?? DEFAULT_IGNORE_FILES;
  const extraIgnorePrefixes = options.extraIgnorePrefixes ?? [];

  const files: FileEntry[] = [];
  let truncated = false;

  async function walk(dir: string, depth: number): Promise<void> {
    if (truncated) return;
    if (depth > maxDepth) return;

    let entries;
    try {
      entries = await fs.readdir(dir, { withFileTypes: true });
    } catch {
      return;
    }

    // Stable order for reproducible agent output
    entries.sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (truncated) return;
      const abs = path.join(dir, entry.name);
      const rel = toPosix(path.relative(root, abs));

      if (extraIgnorePrefixes.some((p) => rel === p || rel.startsWith(`${p}/`))) {
        continue;
      }

      if (shouldIgnoreName(entry.name, entry.isDirectory(), ignoreDirs, ignoreFiles)) {
        continue;
      }

      if (entry.isDirectory()) {
        await walk(abs, depth + 1);
        continue;
      }

      if (!entry.isFile()) continue;

      const ext = path.extname(entry.name).toLowerCase();
      if (extensions && extensions.size > 0 && !extensions.has(ext)) {
        // Always allow extensionless suspicious names like Dockerfile? skip for v1.
        if (entry.name !== "Dockerfile" && entry.name !== "Makefile") {
          continue;
        }
      }

      let size = 0;
      try {
        const st = await fs.stat(abs);
        size = st.size;
      } catch {
        continue;
      }

      files.push({ absolutePath: abs, relativePath: rel, size, ext });
      if (files.length >= maxFiles) {
        truncated = true;
        return;
      }
    }
  }

  await walk(root, 0);
  return { files, truncated };
}

/** Read a file with a hard byte limit; content may be truncated. */
export async function readProjectFile(
  projectRoot: string,
  relativeOrAbsolute: string,
  maxBytes: number = DEFAULT_MAX_FILE_BYTES,
): Promise<ReadFileResult> {
  const root = await normalizeProjectRoot(projectRoot);
  const abs = path.isAbsolute(relativeOrAbsolute)
    ? resolveSafePath(root, path.relative(root, relativeOrAbsolute))
    : resolveSafePath(root, relativeOrAbsolute);

  const buf = await fs.readFile(abs);
  const truncated = buf.length > maxBytes;
  const slice = truncated ? buf.subarray(0, maxBytes) : buf;
  // Treat as UTF-8; binary files will still produce a string (agent can ignore).
  const content = slice.toString("utf8");
  return {
    relativePath: toPosix(path.relative(root, abs)),
    content,
    truncated,
    size: buf.length,
  };
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
export async function profileProject(projectRoot: string): Promise<ProjectProfile> {
  const root = await normalizeProjectRoot(projectRoot);
  const topLevelEntries = await listTopLevel(root);

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

  // Sample walk for language presence (cheap caps)
  const { files } = await walkProject(root, {
    maxFiles: 80,
    maxDepth: 6,
    extensions: new Set([".ts", ".tsx", ".js", ".jsx", ".swift", ".json", ".pbxproj", ".plist"]),
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

/** Build a standard MCP tool success payload with JSON text + structuredContent. */
export function toolSuccess<T extends object>(
  data: T,
  options: { markdown?: string; responseFormat?: "json" | "markdown" } = {},
): {
  content: { type: "text"; text: string }[];
  structuredContent: T;
} {
  const format = options.responseFormat ?? "json";
  let text: string;
  if (format === "markdown" && options.markdown) {
    text = options.markdown;
  } else {
    text = JSON.stringify(data, null, 2);
  }
  const { text: limited, truncated } = truncateText(text);
  const structured = truncated
    ? ({ ...data, truncated: true } as T & { truncated: boolean })
    : data;
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
