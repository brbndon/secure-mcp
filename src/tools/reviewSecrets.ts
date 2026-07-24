/**
 * Tool: secure_mcp_review_secrets
 * Defensive identification of secret exposure for rotation and remediation.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import type { z } from "zod";
import {
  findLineNumber,
  normalizeProjectRoot,
  readProjectFile,
  snippetAround,
  toolError,
  toolSuccess,
  walkProject,
} from "../lib/filesystem.js";
import type { Finding } from "../lib/types.js";
import {
  buildFinding,
  createFindingIdFactory,
  ProjectRootInput,
} from "../knowledge/findings-schema.js";
import { SECRET_PATTERNS } from "../knowledge/common.js";
import { NEXTJS_PATTERNS } from "../knowledge/nextjs.js";
import { SWIFT_PATTERNS } from "../knowledge/swift.js";

const InputSchema = ProjectRootInput;
type Input = z.infer<typeof InputSchema>;

const FALSE_POSITIVE_HINTS =
  /example|sample|placeholder|your[_-]?key|xxx+|todo|changeme|dummy|fake|test[_-]?key|process\.env/i;

function redactedEvidence(raw: string): string {
  // Avoid echoing full secrets back into agent logs when possible
  if (raw.length <= 24) return raw.replace(/[A-Za-z0-9]/g, (ch, i) => (i < 4 ? ch : "*"));
  return raw.slice(0, 8) + "…" + raw.slice(-4).replace(/./g, "*") + ` (len=${raw.length})`;
}

const TOOL_DESCRIPTION = `Defensive secure-code-review tool: identify potential hardcoded secrets and unsafe secret handling so the development team can rotate credentials and harden configuration.

PURPOSE (defensive only)
- Find likely secret material and mis-scoped public env vars.
- Classify severity and confidence; redaction is applied to evidence where practical.
- Recommend rotation, removal from source, and proper secret stores.
- Never teach how to misuse discovered credentials or expand access.

MANDATORY AGENT WORKFLOW
1. Inventory the repo; note env files and config paths.
2. Run this tool; treat hits as candidates.
3. Confirm in-repo context (fixture vs production, placeholder vs live-looking values).
4. For confirmed issues: evidence → classify → impact_if_unremediated → remediation (including rotation) → residual_risk → verification.
5. Urge immediate rotation for anything that appears to be a live production secret.
6. Merge into secure_mcp_produce_findings for the remediation report.
7. Continue until secrets-related classes for the stack are reviewed with evidence.

WHAT THIS TOOL CHECKS
- Private key blocks, cloud tokens (AWS, GitHub, Stripe, Slack), generic API key assignments, JWT-like strings
- Committed .env files (excluding .env.example)
- Next.js NEXT_PUBLIC_ secret-like names and client-bundle risks
- Swift UserDefaults / hardcoded password-like patterns

Args:
  - project_root, stack, max_files, response_format

Returns:
  findings[] category secrets, with required remediation fields. Evidence is partially redacted.

GUARDRAILS
- Read-only filesystem inspection.
- Do not exfiltrate secrets to external systems; help the owners fix their repository.`;

export function registerReviewSecrets(server: McpServer): void {
  server.registerTool(
    "secure_mcp_review_secrets",
    {
      title: "Review secrets for remediation",
      description: TOOL_DESCRIPTION,
      inputSchema: InputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params: Input) => {
      try {
        const root = await normalizeProjectRoot(params.project_root);
        const nextId = createFindingIdFactory("SEC");
        const findings: Finding[] = [];
        const filesScanned: string[] = [];

        const { files, truncated } = await walkProject(root, {
          maxFiles: params.max_files ?? 500,
          extensions: new Set([
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
            ".plist",
            ".entitlements",
            ".toml",
            ".properties",
            ".txt",
            ".pem",
            ".key",
          ]),
        });

        const envish = files.filter(
          (f) =>
            f.relativePath.includes(".env") ||
            f.ext === ".pem" ||
            f.ext === ".key" ||
            f.relativePath.endsWith("credentials.json") ||
            f.relativePath.endsWith("service-account.json"),
        );

        for (const file of files) {
          if (file.size > 256 * 1024) continue;
          if (file.relativePath.includes(".min.")) continue;

          let content: string;
          try {
            content = (await readProjectFile(root, file.relativePath)).content;
          } catch {
            continue;
          }
          filesScanned.push(file.relativePath);

          if (
            /(^|\/)\.env($|\.(local|development|production|staging))/i.test(file.relativePath) &&
            !file.relativePath.endsWith(".example")
          ) {
            findings.push(
              buildFinding({
                id: nextId(),
                title: "Environment file present in tree",
                description:
                  "A .env file was found. Confirm it is gitignored and does not contain production secrets in the working tree under review.",
                severity: "medium",
                confidence: "medium",
                category: "secrets",
                file: file.relativePath,
                evidence: file.relativePath,
                impact_if_unremediated:
                  "Local env files that are committed or shared can leak production credentials.",
                remediation:
                  "Ensure .env* (except .env.example) is gitignored; use secret managers for production; scrub history if secrets were committed.",
                residual_risk: "Developer machines may still hold copies of rotated secrets.",
                verification_suggestion:
                  "Check .gitignore and git history for env files; confirm CI uses secret stores.",
                cwe: "CWE-200",
                tags: ["env-file", "remediation"],
              }),
            );
          }

          for (const pattern of SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;
            let match: RegExpExecArray | null;
            let hits = 0;
            while ((match = pattern.regex.exec(content)) !== null && hits < 10) {
              const full = match[0];
              if (
                FALSE_POSITIVE_HINTS.test(full) ||
                FALSE_POSITIVE_HINTS.test(snippetAround(content, match.index, 40))
              ) {
                if (!pattern.name.includes("Private key") && !pattern.name.includes("AWS")) {
                  continue;
                }
              }
              hits++;
              findings.push(
                buildFinding({
                  id: nextId(),
                  title: `Possible secret: ${pattern.name}`,
                  description: `Matched heuristic for ${pattern.name}. Verify whether this is a real credential and whether it is still active; if so, remediate and rotate.`,
                  severity: pattern.severity,
                  confidence: FALSE_POSITIVE_HINTS.test(full) ? "low" : "high",
                  category: "secrets",
                  file: file.relativePath,
                  line: findLineNumber(content, match.index),
                  evidence: redactedEvidence(full),
                  impact_if_unremediated: pattern.impact_if_unremediated,
                  remediation: pattern.remediation,
                  residual_risk:
                    "Secrets may remain in git history or secondary systems until rotated and purged.",
                  verification_suggestion:
                    "Confirm rotation in the provider console; re-scan the repository and history; ensure CI secrets are updated.",
                  cwe: "CWE-798",
                  tags: ["secrets", pattern.name, "remediation"],
                }),
              );
            }
          }

          if (params.stack !== "swift") {
            for (const p of NEXTJS_PATTERNS.filter(
              (x) => x.id.includes("PUBLIC") || x.id.includes("USE-CLIENT"),
            )) {
              p.regex.lastIndex = 0;
              let match: RegExpExecArray | null;
              while ((match = p.regex.exec(content)) !== null) {
                findings.push(
                  buildFinding({
                    id: nextId(),
                    title: p.title,
                    description:
                      "Next.js client-bundle secret exposure pattern matched. Secrets must not be public env or client-imported.",
                    severity: p.severity,
                    confidence: "medium",
                    category: "secrets",
                    stack: "nextjs",
                    file: file.relativePath,
                    line: findLineNumber(content, match.index),
                    evidence: snippetAround(content, match.index),
                    impact_if_unremediated: p.impact_if_unremediated,
                    remediation: p.recommendation,
                    residual_risk: "Old client bundles may still contain rotated secrets until redeployed.",
                    verification_suggestion:
                      "Inspect production client bundles and env naming conventions after the fix.",
                    cwe: p.cwe,
                    tags: ["nextjs", "secrets", "remediation"],
                  }),
                );
              }
            }
          }

          if (params.stack === "auto" || params.stack === "swift") {
            for (const p of SWIFT_PATTERNS.filter(
              (x) => x.id.includes("USERDEFAULTS") || x.id.includes("HARDCODED"),
            )) {
              p.regex.lastIndex = 0;
              let match: RegExpExecArray | null;
              while ((match = p.regex.exec(content)) !== null) {
                findings.push(
                  buildFinding({
                    id: nextId(),
                    title: p.title,
                    description: "Swift secret-handling heuristic matched — review storage and remove hardcoded secrets.",
                    severity: p.severity,
                    confidence: "medium",
                    category: "secrets",
                    stack: "swift",
                    file: file.relativePath,
                    line: findLineNumber(content, match.index),
                    evidence: snippetAround(content, match.index),
                    impact_if_unremediated: p.impact_if_unremediated,
                    remediation: p.recommendation,
                    residual_risk: "Old app installs may retain secrets until users upgrade.",
                    verification_suggestion:
                      "Audit Keychain migration paths and confirm no secrets remain in UserDefaults or source.",
                    cwe: p.cwe,
                    tags: ["swift", "secrets", "remediation"],
                  }),
                );
              }
            }
          }
        }

        const order = { critical: 5, high: 4, medium: 3, low: 2, info: 1 };
        findings.sort((a, b) => order[b.severity] - order[a.severity]);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Secrets review: ${findings.length} potential issue(s) across ${filesScanned.length} file(s). Rotate confirmed live secrets; remediate storage — do not misuse credentials.`,
          findings,
          env_related_files: envish.map((f) => f.relativePath),
          truncated,
          applied_pack_ids: ["core", "secrets"] as const,
          notes: [
            "Defensive secret hygiene only: identify → classify → rotate/remediate.",
            "Evidence is partially redacted; open the file locally to confirm.",
            "Never use discovered credentials against systems — only help owners fix and rotate.",
            "Pack ids are for traceability; load checklists via secure_mcp_get_knowledge_pack when needed.",
          ],
        };

        const md = [
          `# Secrets review (remediation focused)`,
          data.summary,
          "",
          ...findings.slice(0, 40).map(
            (f) =>
              `### ${f.id} [${f.severity}/${f.confidence}] ${f.title}\n` +
              `- ${f.file ?? "?"}:${f.line ?? "?"}\n` +
              `- Evidence: ${f.evidence}\n` +
              `- Remediation: ${f.remediation}\n`,
          ),
        ].join("\n");

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
