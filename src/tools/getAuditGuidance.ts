/**
 * Tool: secure_mcp_get_audit_guidance
 * Lightweight on-demand detailed guidance for agents (extracted from bloated per-tool descriptions).
 * Call this when you need the full MANDATORY WORKFLOW / GUARDRAILS instead of embedding in every tool desc.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/envelope.js";

const InputSchema = z
  .object({
    section: z
      .enum([
        "overview",
        "workflow",
        "authentication",
        "injection-risks",
        "secrets",
        "threat-model",
        "architecture",
        "findings",
        "all",
      ])
      .default("overview")
      .describe("Which section of defensive audit guidance to return (default overview)."),
    response_format: z.enum(["json", "markdown"]).default("markdown"),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

const GUIDANCE: Record<string, string> = {
  overview: `Defensive secure-code-review MCP server for agents.

MANDATE
- Identify potential weaknesses in owned codebases.
- Classify (severity/confidence/category/CWE).
- Recommend concrete remediation + verification.
- Strictly remediation-focused; no exploit generation, no offensive guidance, no using secrets.

All tools are read-only, path-sandboxed, size-capped, and output using the shared Finding schema:
evidence → classification → impact_if_unremediated → remediation → residual_risk → verification_suggestion.

Call secure_mcp_get_audit_guidance with other sections for details. Prefer multi-phase: list → architecture → packs → category tools → produce_findings.`,

  workflow: `MANDATORY MULTI-PHASE AGENT WORKFLOW (defensive only)
Phase 1: secure_mcp_list_project_structure (inventory)
Phase 2: secure_mcp_analyze_architecture (stacks, typed surfaces, coverage_gaps, priority_paths, security_brief, recommended_packs, pack_batches, trust boundaries)
         secure_mcp_get_knowledge_pack (start with pack_batches[0], detail=summary; max 6 ids/call; fair sample)
         (optional) secure_mcp_build_remediation_threat_model
Phase 3: secure_mcp_check_authentication
         secure_mcp_analyze_injection_risks
         secure_mcp_review_secrets   (parallel ok)
         then sample zero-hit high-value surfaces from architecture priority_paths/coverage_gaps
Phase 4: Open files for evidence, trace data flows (read-only); disposition = reportable|needs_review|suppressed|not_applicable|deferred|fixed with reason/evidence.
Phase 5: secure_mcp_produce_findings (prefer reportable open findings; fixed is counted but not prioritised over open work)
Phase 6: Human narrative from the report.

PROGRESSIVE RULE: Do not load packs before architecture. Use focus_paths for scoped drill-down / PR diffs (host resolves git paths; server never runs git).
Never treat heuristic output as final without reading source. Keep intermediate artifacts (architecture is the security brief).
Sub-agents must stay defensive (mapper, specialist, reporter — no "exploit" roles).
`,

  authentication: `secure_mcp_check_authentication
PURPOSE (defensive): locate incomplete session validation, hardcoded creds, weak TLS, middleware-only checks, insecure mobile storage.
WORKFLOW: inventory first → run tool → read cited files + verify authz + secret handling → fill full Finding schema for confirmed.
GUARDRAILS: read-only; confirm data flow; pair auth with explicit authz; no bypass recipes.`,

  "injection-risks": `secure_mcp_analyze_injection_risks
PURPOSE (defensive): find untrusted input to dangerous sinks (sql concat, eval, command, innerHTML, path, redirects).
WORKFLOW: after arch, run, then manually trace from source to sink for high/critical; complete remediation fields.
GUARDRAILS: heuristics only; verify before confirming; use safe APIs / allowlists / parameterized queries.`,

  secrets: `secure_mcp_review_secrets
PURPOSE (defensive): detect committed secrets, mis-scoped public env, unsafe storage.
WORKFLOW: inventory env/config paths → run → confirm live vs placeholder → immediate rotate for real creds; full Finding.
GUARDRAILS: evidence redacted where possible; rotate + remove from git history; never misuse discovered values.`,

  "threat-model": `secure_mcp_build_remediation_threat_model
PURPOSE (defensive): STRIDE fragments to prioritise controls and hardening (S/T/R/I/D/E).
WORKFLOW: after arch, call with optional focus_area/assets; use recommended_controls while doing category scans; convert high residual to seeds.
GUARDRAILS: only for owners strengthening their own system; no attack plans.`,

  architecture: `secure_mcp_analyze_architecture
Returns stacks, legacy surface path buckets, typed surfaces (kind/exposure/auth_expectation/paths), coverage_gaps, priority_paths, security_brief, trust boundaries, recommended_packs/pack_batches, checklist_seed.
Retain architecture as the security brief. After category tools, sample zero-hit high-value surfaces from coverage_gaps/priority_paths.
Host agents may map PR diffs into focus_paths; the server does not run git.`,

  findings: `secure_mcp_produce_findings
Every finding passed in must have: evidence, impact_if_unremediated, remediation, residual_risk, verification_suggestion + classification.
Dispositions: reportable (open confirmed), needs_review, suppressed, not_applicable, deferred, fixed (revalidated remediation with reason/evidence).
Prefer reportable for the final rollup; fixed is counted in candidate_disposition_counts but does not dominate remediation_priority.
Use dedupe, filters. Output is prioritised remediation report.
Never rewrite into exploit content.`,

  all: `See sections: overview, workflow, authentication, injection-risks, secrets, threat-model, architecture, findings.
Full details also in docs/agent-workflow.md and skills/security-auditor.md.
Always stay defensive and owner-focused.`,
};

const GUIDANCE_SECTION_ORDER = [
  "overview",
  "workflow",
  "architecture",
  "authentication",
  "injection-risks",
  "secrets",
  "threat-model",
  "findings",
] as const;

GUIDANCE.all = GUIDANCE_SECTION_ORDER.map(
  (section) => `## ${section}\n${GUIDANCE[section]}`,
).join("\n\n");

export function registerGetAuditGuidance(server: McpServer): void {
  server.registerTool(
    "secure_mcp_get_audit_guidance",
    {
      title: "Get detailed defensive audit guidance (on demand)",
      description:
        "Returns full agent workflow, guardrails, and category-specific guidance extracted from tool docs. Call on demand instead of bloating every tool description. Args: section (overview|workflow|...|all), response_format.",
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
        const sec = params.section ?? "overview";
        const text = GUIDANCE[sec] ?? GUIDANCE.overview;
        const data = {
          ok: true as const,
          section: sec,
          guidance: text,
          note: "This is the detailed defensive workflow. Use short tool descriptions for normal calls; request this when you need the full context.",
        };
        const md = `# Defensive Audit Guidance — ${sec}\n\n${text}\n`;
        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(error, "Use a valid section or omit for overview.");
      }
    },
  );
}
