/**
 * Shared Markdown rendering for untrusted audit output.
 *
 * All caller/repository values are escaped here; tools provide semantic
 * document sections instead of assembling Markdown syntax themselves.
 */

import type { Finding } from "./types.js";
import { redactedEvidence } from "./redact.js";

/** Escape untrusted values before placing them in Markdown text output. */
export function escapeMarkdown(value: string): string {
  return redactedEvidence(value)
    .replace(/\r\n?|\n/g, " ")
    .replace(/([\\`*_{}\[\]()#+.!|<>~=\-:\/@&$%^?'",;])/g, "\\$1");
}

/** Render untrusted evidence as a bounded inline code value. */
export function markdownCode(value: string): string {
  return `\`${redactedEvidence(value).replace(/\r\n?|\n/g, "\\n").replace(/`/g, "\\u0060")}\``;
}

export interface MarkdownField {
  label: string;
  value: string;
  labelCode?: boolean;
  valueCode?: boolean;
}

export interface MarkdownSection {
  heading: string;
  level?: 2 | 3;
  paragraphs?: readonly string[];
  fields?: readonly MarkdownField[];
  bullets?: readonly string[];
}

export interface FindingMarkdownOptions {
  detail?: "compact" | "full";
  headingLevel?: 2 | 3;
}

function renderField(field: MarkdownField, bullet: boolean): string {
  const label = field.labelCode
    ? markdownCode(field.label)
    : `**${escapeMarkdown(field.label)}:**`;
  const value = field.valueCode ? markdownCode(field.value) : escapeMarkdown(field.value);
  return `${bullet ? "- " : ""}${label} ${value}`;
}

/** Canonical finding renderer used by reports and category-tool summaries. */
export function renderFindingMarkdown(
  finding: Finding,
  options: FindingMarkdownOptions = {},
): string {
  const detail = options.detail ?? "compact";
  const headingLevel = options.headingLevel ?? 3;
  const lines = [
    `${"#".repeat(headingLevel)} [${escapeMarkdown(`${finding.severity}/${finding.confidence}`)}] ${escapeMarkdown(finding.id)}: ${escapeMarkdown(finding.title)}`,
    "",
  ];

  if (detail === "full") {
    lines.push("#### Classification");
    lines.push(`- **Severity:** ${finding.severity}`);
    lines.push(`- **Confidence:** ${finding.confidence}`);
    lines.push(`- **Category:** ${escapeMarkdown(finding.category)}`);
    if (finding.cwe) lines.push(`- **CWE:** ${escapeMarkdown(finding.cwe)}`);
    if (finding.owasp) lines.push(`- **OWASP:** ${escapeMarkdown(finding.owasp)}`);
    if (finding.file) {
      lines.push(
        `- **Location:** ${escapeMarkdown(`${finding.file}${finding.line ? `:${finding.line}` : ""}`)}`,
      );
    }
    if (finding.instance_id) {
      lines.push(`- **Stable instance:** ${escapeMarkdown(finding.instance_id)}`);
    }
    if (finding.rule_family) {
      lines.push(`- **Rule family:** ${escapeMarkdown(finding.rule_family)}`);
    }
    if (finding.root_control) {
      lines.push(`- **Root control:** ${escapeMarkdown(finding.root_control)}`);
    }
    if (finding.disposition) {
      lines.push(`- **Disposition:** ${escapeMarkdown(finding.disposition)}`);
    }
    if (finding.disposition_reason) {
      lines.push(`- **Disposition reason:** ${escapeMarkdown(finding.disposition_reason)}`);
    }
    lines.push("");
    lines.push("#### Evidence");
    lines.push(escapeMarkdown(finding.description));
    lines.push("");
    lines.push(markdownCode(finding.evidence));
    if (finding.source || finding.control || finding.sink) {
      lines.push("", "#### Proof context");
      if (finding.source) lines.push(`- **Source:** ${escapeMarkdown(finding.source)}`);
      if (finding.control) lines.push(`- **Control:** ${escapeMarkdown(finding.control)}`);
      if (finding.sink) lines.push(`- **Sink:** ${escapeMarkdown(finding.sink)}`);
    }
    for (const [heading, items] of [
      ["Counterevidence", finding.counterevidence],
      ["Proof gap", finding.proof_gap],
      ["Validation", finding.validation],
    ] as const) {
      if (!items?.length) continue;
      lines.push("", `#### ${heading}`);
      for (const item of items) lines.push(`- ${escapeMarkdown(item)}`);
    }
    lines.push("", "#### Impact if unremediated", escapeMarkdown(finding.impact_if_unremediated));
    lines.push("", "#### Remediation", escapeMarkdown(finding.remediation));
    lines.push("", "#### Residual risk", escapeMarkdown(finding.residual_risk));
    lines.push("", "#### Verification suggestion", escapeMarkdown(finding.verification_suggestion));
    return lines.join("\n");
  }

  lines.push(escapeMarkdown(finding.description));
  if (finding.file) {
    lines.push(
      `- **Evidence location:** ${escapeMarkdown(`${finding.file}${finding.line ? `:${finding.line}` : ""}`)}`,
    );
  }
  lines.push(`- **Evidence:** ${escapeMarkdown(finding.evidence)}`);
  lines.push(`- **Impact if unremediated:** ${escapeMarkdown(finding.impact_if_unremediated)}`);
  lines.push(`- **Remediation:** ${escapeMarkdown(finding.remediation)}`);
  return lines.join("\n");
}

/** Render a complete escaped Markdown document from semantic sections. */
export function renderMarkdownDocument(options: {
  title: string;
  summary?: string;
  notice?: string;
  metadata?: readonly MarkdownField[];
  sections?: readonly MarkdownSection[];
  findings?: readonly Finding[];
  findingOptions?: FindingMarkdownOptions;
}): string {
  const lines = [`# ${escapeMarkdown(options.title)}`];
  if (options.notice) lines.push("", `> ${escapeMarkdown(options.notice)}`);
  if (options.summary) lines.push("", escapeMarkdown(options.summary));
  if (options.metadata?.length) {
    lines.push("");
    for (const field of options.metadata) lines.push(renderField(field, false));
  }
  for (const section of options.sections ?? []) {
    lines.push("", `${"#".repeat(section.level ?? 2)} ${escapeMarkdown(section.heading)}`);
    for (const paragraph of section.paragraphs ?? []) {
      lines.push("", escapeMarkdown(paragraph));
    }
    for (const field of section.fields ?? []) lines.push(renderField(field, true));
    for (const bullet of section.bullets ?? []) lines.push(`- ${escapeMarkdown(bullet)}`);
  }
  for (const finding of options.findings ?? []) {
    lines.push("", renderFindingMarkdown(finding, options.findingOptions));
  }
  return lines.join("\n");
}

/** Full remediation report renderer retained as the produce-findings contract. */
export function renderFindingsReportMarkdown(options: {
  title: string;
  projectRoot?: string;
  findings: readonly Finding[];
  counts: Readonly<Record<string, number>>;
}): string {
  return renderMarkdownDocument({
    title: options.title,
    notice:
      "Defensive secure-code-review report. Goal: help the development team harden the codebase. Do not include exploit or attack PoC content.",
    metadata: [
      ...(options.projectRoot ? [{ label: "Project", value: options.projectRoot }] : []),
      { label: "Total findings", value: String(options.findings.length) },
    ],
    sections: [
      {
        heading: "Summary by severity (remediation priority)",
        fields: Object.entries(options.counts).map(([label, count]) => ({
          label,
          value: String(count),
        })),
      },
      { heading: "Findings" },
    ],
    findings: options.findings,
    findingOptions: { detail: "full", headingLevel: 3 },
  });
}
