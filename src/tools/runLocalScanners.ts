/**
 * Tool: secure_mcp_run_local_scanners
 * Optional, default-off composition of locally-installed scanners (semgrep,
 * gitleaks). Shells out only to binaries already on PATH — no scanner is an npm
 * dependency and no ruleset is downloaded unless the caller explicitly opts in.
 * Results are mapped into the secure-mcp candidate-finding shape (needs_review).
 */

import { execFile as execFileCb } from "node:child_process";
import { promisify } from "node:util";
import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import {
  normalizeAuthorizedProjectRoot,
  readProjectFileIfExists,
} from "../lib/filesystem.js";
import { redactedEvidence } from "../lib/redact.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import type { Finding, Severity } from "../lib/types.js";
import {
  buildFinding,
  createFindingIdFactory,
  MAX_PROJECT_ROOT_LENGTH,
} from "../knowledge/findings-schema.js";

const execFileAsync = promisify(execFileCb);

/** Real execFile wrapper matching ExecFileFn (utf8 strings, no shell). */
const defaultExecFile: ExecFileFn = (file, args, options) =>
  execFileAsync(file, args, { ...options, encoding: "utf8" }) as Promise<{
    stdout: string;
    stderr: string;
  }>;

export type ScannerId = "semgrep" | "gitleaks";

export type ExecFileFn = (
  file: string,
  args: string[],
  options: { cwd: string; timeout: number; maxBuffer: number; env?: NodeJS.ProcessEnv },
) => Promise<{ stdout: string; stderr: string }>;

export type BinaryRunResult =
  | { status: "ok"; stdout: string; stderr: string }
  | { status: "missing"; binary: string }
  | { status: "timeout"; binary: string }
  | { status: "error"; binary: string; message: string };

const DEFAULT_TIMEOUT_SECONDS = 120;
const MAX_TIMEOUT_SECONDS = 600;
const MAX_BUFFER_BYTES = 4 * 1024 * 1024;

const SEMGREP_CONFIG_CANDIDATES = [".semgrep.yml", ".semgrep.yaml", "semgrep.yml", "semgrep.yaml"];

/** Environment gate: SECURE_MCP_LOCAL_SCANNERS must be "1"/"true" to allow any scanner. */
export function scannerEnvEnabled(value: string | undefined): boolean {
  return value === "1" || (value ?? "").toLowerCase() === "true";
}

/** Scanners only run when the caller opts in AND the server env gate is on. */
export function scannersEnabled(enable: boolean, env: NodeJS.ProcessEnv): boolean {
  return enable === true && scannerEnvEnabled(env.SECURE_MCP_LOCAL_SCANNERS);
}

/** Minimal env for scanner children — no MCP secrets or caller extras. */
export function scannerChildEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out: NodeJS.ProcessEnv = {};
  for (const key of ["PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TEMP", "TMP"]) {
    if (env[key] !== undefined) out[key] = env[key];
  }
  for (const [key, value] of Object.entries(env)) {
    if (key.startsWith("SEMGREP_") || key.startsWith("GITLEAKS_")) out[key] = value;
  }
  return out;
}

/** Run a binary with cwd, timeout, and no shell; classify the outcome. */
export async function runBinary(
  execFile: ExecFileFn,
  binary: string,
  args: string[],
  cwd: string,
  timeoutMs: number,
): Promise<BinaryRunResult> {
  try {
    const { stdout, stderr } = await execFile(binary, args, {
      cwd,
      timeout: timeoutMs,
      maxBuffer: MAX_BUFFER_BYTES,
      env: scannerChildEnv(),
    });
    return { status: "ok", stdout, stderr };
  } catch (error) {
    const err = error as {
      code?: string | number;
      killed?: boolean;
      signal?: string;
      stdout?: string;
      stderr?: string;
    };
    if (err.code === "ENOENT") return { status: "missing", binary };
    if (err.killed || err.signal === "SIGKILL" || err.signal === "SIGTERM" || err.code === "ETIMEDOUT") {
      return { status: "timeout", binary };
    }
    // semgrep/gitleaks exit 1 when they find issues; stdout is still a completed
    // report. Any other exit code is a hard failure even if stdout carries JSON
    // (e.g. semgrep config/fatal errors print an errors document), so it must
    // surface as status "error" rather than a false clean.
    if (err.code === 1 && typeof err.stdout === "string") {
      return { status: "ok", stdout: err.stdout, stderr: typeof err.stderr === "string" ? err.stderr : "" };
    }
    return {
      status: "error",
      binary,
      message: redactedEvidence(error instanceof Error ? error.message : String(error)),
    };
  }
}

interface MappedFinding {
  title: string;
  severity: Severity;
  category: string;
  file?: string;
  line?: number;
  evidence: string;
  cwe?: string;
  rule_family: string;
}

function severityFromSemgrep(value: string | undefined): Severity {
  switch ((value ?? "").toUpperCase()) {
    case "ERROR":
      return "high";
    case "WARNING":
      return "medium";
    case "INFO":
      return "low";
    default:
      return "low";
  }
}

/**
 * Map semgrep --json output to a bounded subset of candidate findings.
 * Returns null when the output is not JSON or not the expected shape, so a
 * misbehaving scanner is surfaced as an error instead of a false clean.
 */
export function parseSemgrepJson(stdout: string): MappedFinding[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  const results = (parsed as { results?: unknown[] })?.results;
  if (!Array.isArray(results)) return null;
  const out: MappedFinding[] = [];
  for (const raw of results.slice(0, 200)) {
    const r = raw as {
      check_id?: string;
      path?: string;
      start?: { line?: number };
      extra?: { message?: string; severity?: string; metadata?: { cwe?: string[] } };
    };
    if (!r.check_id) continue;
    out.push({
      title: r.check_id,
      severity: severityFromSemgrep(r.extra?.severity),
      category: "static-analysis",
      file: r.path,
      line: r.start?.line,
      evidence: redactedEvidence(r.extra?.message ?? r.check_id),
      cwe: r.extra?.metadata?.cwe?.[0],
      rule_family: `semgrep.${r.check_id}`,
    });
  }
  return out;
}

/**
 * Map gitleaks JSON output to candidate findings (secret content never included).
 * Returns null when the output is not JSON or not an array, so a misbehaving
 * scanner is surfaced as an error instead of a false clean.
 */
export function parseGitleaksJson(stdout: string): MappedFinding[] | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    return null;
  }
  if (!Array.isArray(parsed)) return null;
  const out: MappedFinding[] = [];
  for (const raw of parsed.slice(0, 200)) {
    const r = raw as {
      RuleID?: string;
      Description?: string;
      File?: string;
      StartLine?: number;
    };
    if (!r.RuleID) continue;
    out.push({
      title: r.Description ?? r.RuleID,
      severity: "high",
      category: "secrets",
      file: r.File,
      line: r.StartLine,
      evidence: redactedEvidence(
        `Secret match reported by gitleaks rule ${r.RuleID} at ${r.File ?? "(unknown)"}:${r.StartLine ?? 1}. Raw secret value is redacted.`,
      ),
      rule_family: `gitleaks.${r.RuleID}`,
    });
  }
  return out;
}

const InputSchema = z
  .object({
    project_root: z
      .string()
      .min(1)
      .max(MAX_PROJECT_ROOT_LENGTH)
      .describe("Allowlisted root to scan. Scanners run with cwd=project_root and never outside it."),
    enable: z
      .boolean()
      .default(false)
      .describe(
        "Must be true AND the server env SECURE_MCP_LOCAL_SCANNERS must be enabled for any scanner to run. Default false.",
      ),
    allow_remote_rules: z
      .boolean()
      .default(false)
      .describe(
        "If true, semgrep may fetch remote rules when no local config is present (not recommended). Default false — offline/custom config only.",
      ),
    timeout_seconds: z
      .number()
      .int()
      .min(1)
      .max(MAX_TIMEOUT_SECONDS)
      .default(DEFAULT_TIMEOUT_SECONDS)
      .describe(`Per-scanner timeout (default ${DEFAULT_TIMEOUT_SECONDS}, max ${MAX_TIMEOUT_SECONDS})`),
    response_format: z
      .enum(["json", "markdown"])
      .default("json")
      .describe("json for structured agent processing; markdown for human-readable summaries"),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

interface ScannerStatus {
  id: ScannerId;
  status: "completed" | "skipped" | "missing" | "timeout" | "error";
  findings: number;
  note?: string;
}

function scannerFinding(factory: () => string, scannerId: ScannerId, mapped: MappedFinding): Finding {
  return buildFinding({
    id: factory(),
    title: mapped.title,
    description: mapped.evidence,
    severity: mapped.severity,
    confidence: "low",
    category: mapped.category,
    ...(mapped.file ? { file: mapped.file } : {}),
    ...(mapped.line ? { line: mapped.line } : {}),
    evidence: mapped.evidence,
    impact_if_unremediated:
      "A local scanner flagged this location; impact depends on confirmation and reachability. Treat as a candidate, not a confirmed finding.",
    remediation:
      "Review the flagged location against the scanner rule and apply the corresponding hardening fix; then re-run the scanner to confirm.",
    residual_risk: "The scanner does not prove reachability; a confirmed issue may recur elsewhere.",
    verification_suggestion:
      "Re-run the local scanner after remediation and confirm the candidate no longer appears.",
    ...(mapped.cwe ? { cwe: mapped.cwe } : {}),
    rule_family: mapped.rule_family,
    source: `local scanner: ${scannerId}`,
    tags: [`scanner:${scannerId}`],
    disposition: "needs_review",
  });
}

export function registerRunLocalScanners(
  server: McpServer,
  config: ServerConfig = loadConfig(),
  execFile: ExecFileFn = defaultExecFile,
): void {
  server.registerTool(
    "secure_mcp_run_local_scanners",
    {
      title: "Run local scanners (optional, default off)",
      description: `Defensive secure-code-review tool: optionally compose locally-installed scanners (semgrep, gitleaks) into the secure-mcp candidate-finding contract.

PURPOSE (defensive only)
- Orchestrate scanners you already trust and install; secure-mcp shells out only (no scanner npm dependency).
- Offline-first: semgrep uses a local config (.semgrep.yml / semgrep.yml) unless allow_remote_rules=true.
- Default off: requires enable=true AND server env SECURE_MCP_LOCAL_SCANNERS=1. Missing binaries are a structured skip, not an error.
- Findings are candidates (disposition needs_review) — always confirm before reporting.

Args:
  - project_root (string): allowlisted root; scanners run with cwd=project_root only
  - enable (boolean): default false
  - allow_remote_rules (boolean): default false — allow semgrep to fetch rules when no local config
  - timeout_seconds (number): default ${DEFAULT_TIMEOUT_SECONDS}, max ${MAX_TIMEOUT_SECONDS}
  - response_format (json|markdown): default json

Returns:
  enabled, scanners[] (status + finding count), findings[] (candidate shape), notes.`,
      inputSchema: InputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: true,
      },
    },
    async (params: Input) => {
      try {
        if (!params.enable) {
          const data = {
            ok: true as const,
            project_root: params.project_root,
            enabled: false,
            scanners: [] as ScannerStatus[],
            findings: [] as Finding[],
            notes: [
              "Local scanners are disabled by default. Pass enable=true AND set SECURE_MCP_LOCAL_SCANNERS=1 on the server to run them.",
            ],
          };
          return toolSuccess(data, { responseFormat: params.response_format });
        }

        if (!scannerEnvEnabled(process.env.SECURE_MCP_LOCAL_SCANNERS)) {
          const data = {
            ok: true as const,
            project_root: params.project_root,
            enabled: false,
            scanners: [] as ScannerStatus[],
            findings: [] as Finding[],
            notes: [
              "enable=true but the server env SECURE_MCP_LOCAL_SCANNERS is not enabled — scanners stay off (fail closed).",
            ],
          };
          return toolSuccess(data, { responseFormat: params.response_format });
        }

        const root = await normalizeAuthorizedProjectRoot(params.project_root, config.allowedRoots);
        const timeoutMs = params.timeout_seconds * 1000;
        const findings: Finding[] = [];
        const scanners: ScannerStatus[] = [];

        // semgrep — offline-first: require a local config unless explicitly opted in.
        let semgrepConfig: string | undefined;
        for (const candidate of SEMGREP_CONFIG_CANDIDATES) {
          if (await readProjectFileIfExists(root, candidate, config.maxFileBytes, config.allowedRoots)) {
            semgrepConfig = candidate;
            break;
          }
        }
        const semgrepArgs = semgrepConfig
          ? ["scan", "--json", "--exit-zero", "--metrics=off", "--config", semgrepConfig]
          : params.allow_remote_rules
            ? ["scan", "--json", "--exit-zero", "--metrics=off", "--config", "auto"]
            : null;
        if (semgrepArgs === null) {
          scanners.push({
            id: "semgrep",
            status: "skipped",
            findings: 0,
            note: "No local semgrep config found; set allow_remote_rules=true to fetch rules (offline-safe default is to skip).",
          });
        } else {
          const run = await runBinary(execFile, "semgrep", semgrepArgs, root, timeoutMs);
          if (run.status === "missing") {
            scanners.push({ id: "semgrep", status: "missing", findings: 0 });
          } else if (run.status === "timeout") {
            scanners.push({ id: "semgrep", status: "timeout", findings: 0 });
          } else if (run.status === "error") {
            scanners.push({ id: "semgrep", status: "error", findings: 0, note: run.message });
          } else {
            const mapped = parseSemgrepJson(run.stdout);
            if (mapped === null) {
              scanners.push({
                id: "semgrep",
                status: "error",
                findings: 0,
                note: "semgrep output was not valid JSON; treating the run as failed rather than clean.",
              });
            } else {
              const idFactory = createFindingIdFactory("SEMGREP");
              for (const m of mapped) findings.push(scannerFinding(idFactory, "semgrep", m));
              scanners.push({ id: "semgrep", status: "completed", findings: mapped.length });
            }
          }
        }

        // gitleaks — always offline (local repo scan only).
        const gitleaksRun = await runBinary(
          execFile,
          "gitleaks",
          ["detect", "--no-git", "--no-banner", "--report-format=json", "--exit-code=0"],
          root,
          timeoutMs,
        );
        if (gitleaksRun.status === "missing") {
          scanners.push({ id: "gitleaks", status: "missing", findings: 0 });
        } else if (gitleaksRun.status === "timeout") {
          scanners.push({ id: "gitleaks", status: "timeout", findings: 0 });
        } else if (gitleaksRun.status === "error") {
          scanners.push({ id: "gitleaks", status: "error", findings: 0, note: gitleaksRun.message });
        } else {
          const mapped = parseGitleaksJson(gitleaksRun.stdout);
          if (mapped === null) {
            scanners.push({
              id: "gitleaks",
              status: "error",
              findings: 0,
              note: "gitleaks output was not valid JSON; treating the run as failed rather than clean.",
            });
          } else {
            const idFactory = createFindingIdFactory("GITLEAKS");
            for (const m of mapped) findings.push(scannerFinding(idFactory, "gitleaks", m));
            scanners.push({ id: "gitleaks", status: "completed", findings: mapped.length });
          }
        }

        const data = {
          ok: true as const,
          project_root: root,
          enabled: true,
          scanners,
          findings,
          notes: [
            "Scanner output is mapped to candidate findings (disposition needs_review); confirm each in source before reporting.",
            "Secret values from gitleaks are never included — evidence is redacted.",
            "No ruleset is downloaded unless allow_remote_rules=true was passed.",
          ],
        };

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: renderMarkdownDocument({
            title: "Local scanner results",
            metadata: [
              { label: "Root", value: root },
              { label: "Findings", value: String(findings.length) },
            ],
            sections: [
              {
                heading: "Scanners",
                bullets: scanners.map(
                  (s) => `${s.id}: ${s.status} (${s.findings})${s.note ? ` — ${s.note}` : ""}`,
                ),
              },
            ],
          }),
        });
      } catch (error) {
        return toolError(
          error,
          "Pass an allowlisted project_root and enable the scanner gate (enable=true + SECURE_MCP_LOCAL_SCANNERS=1).",
        );
      }
    },
  );
}
