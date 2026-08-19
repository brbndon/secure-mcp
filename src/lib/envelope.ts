/**
 * MCP output contract for secure-mcp tools.
 *
 * Every tool returns its result through this module: success and error
 * envelopes, character budgeting, and the structuredContent bounds. Keeping
 * the response contract out of `lib/filesystem.js` means a formatting-only
 * tool (e.g. produceFindings, which never touches the disk) does not import
 * the filesystem module, and new tool payload shapes stop leaking into the
 * walk module's shrink-key lists.
 */

import type { CoverageReport } from "./types.js";
import { redactValue, redactedEvidence, UNTRUSTED_OUTPUT_NOTICE } from "./redact.js";

/** Budget applied to tool text and structured responses for agent context. */
export const CHARACTER_LIMIT = 25_000;

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
  "surfaces",
  "coverage_gaps",
  "authz_graph",
  "priority_paths",
  "recommended_packs",
  "pack_batches",
  "checklist_seed",
  "trust_boundaries",
  "notable_dependencies",
  "top_level",
  "threat_highlights",
] as const;

/** Nested coverage arrays that can dominate structuredContent size. */
const COVERAGE_SHRINKABLE_ARRAY_KEYS = [
  "included_paths",
  "excluded_paths",
  "ignored_paths",
  "candidate_dispositions",
  "files_reviewed",
] as const;

/** Legacy architecture path buckets on `surface`. */
const LEGACY_SURFACE_BUCKET_KEYS = [
  "entrypoints",
  "auth_related",
  "config_files",
  "api_routes",
  "data_layer_hints",
] as const;

/** Compact security_brief arrays that can grow with the parent inventory. */
const SECURITY_BRIEF_SHRINKABLE_ARRAY_KEYS = [
  "high_value_surfaces",
  "priority_paths",
  "recommended_packs",
  "trust_boundaries",
  "notes",
] as const;

/** Top-level object arrays whose nested `paths` / `sample_paths` can dominate size. */
const NESTED_PATH_ARRAY_KEYS = ["surfaces", "coverage_gaps"] as const;

function halfArrayIfLarge(value: unknown): { value: unknown; shrunk: boolean } {
  if (Array.isArray(value) && value.length > 1) {
    return { value: value.slice(0, Math.max(1, Math.floor(value.length / 2))), shrunk: true };
  }
  return { value, shrunk: false };
}

function shrinkObjectArrayFields(
  value: unknown,
  keys: readonly string[],
): { value: unknown; shrunk: boolean } {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return { value, shrunk: false };
  }
  const next: Record<string, unknown> = { ...(value as Record<string, unknown>) };
  let shrunk = false;
  for (const key of keys) {
    const result = halfArrayIfLarge(next[key]);
    if (result.shrunk) {
      next[key] = result.value;
      shrunk = true;
    }
  }
  return { value: next, shrunk };
}

function shrinkCoverageArrays(coverage: unknown): { coverage: unknown; shrunk: boolean } {
  const result = shrinkObjectArrayFields(coverage, COVERAGE_SHRINKABLE_ARRAY_KEYS);
  return { coverage: result.value, shrunk: result.shrunk };
}

function shrinkNestedPathFields(item: unknown): { item: unknown; shrunk: boolean } {
  if (!item || typeof item !== "object" || Array.isArray(item)) {
    return { item, shrunk: false };
  }
  const rec = item as Record<string, unknown>;
  let shrunk = false;
  const next: Record<string, unknown> = { ...rec };
  for (const key of ["paths", "sample_paths"] as const) {
    const result = halfArrayIfLarge(next[key]);
    if (result.shrunk) {
      next[key] = result.value;
      shrunk = true;
    }
  }
  return { item: shrunk ? next : item, shrunk };
}

function shrinkNestedPathArrays(items: unknown): { items: unknown; shrunk: boolean } {
  if (!Array.isArray(items) || items.length === 0) {
    return { items, shrunk: false };
  }
  let shrunk = false;
  const next = items.map((item) => {
    const result = shrinkNestedPathFields(item);
    if (result.shrunk) shrunk = true;
    return result.item;
  });
  return { items: shrunk ? next : items, shrunk };
}

function shrinkSecurityBrief(brief: unknown): { brief: unknown; shrunk: boolean } {
  const top = shrinkObjectArrayFields(brief, SECURITY_BRIEF_SHRINKABLE_ARRAY_KEYS);
  if (!top.value || typeof top.value !== "object" || Array.isArray(top.value)) {
    return { brief: top.value, shrunk: top.shrunk };
  }
  const next = top.value as Record<string, unknown>;
  const nested = shrinkNestedPathArrays(next.high_value_surfaces);
  if (!nested.shrunk) {
    return { brief: top.value, shrunk: top.shrunk };
  }
  return { brief: { ...next, high_value_surfaces: nested.items }, shrunk: true };
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
    for (const key of NESTED_PATH_ARRAY_KEYS) {
      const nested = shrinkNestedPathArrays(next[key]);
      if (nested.shrunk) {
        next[key] = nested.items;
        shrunk = true;
      }
    }
    const surfaceResult = shrinkObjectArrayFields(next.surface, LEGACY_SURFACE_BUCKET_KEYS);
    if (surfaceResult.shrunk) {
      next.surface = surfaceResult.value;
      shrunk = true;
    }
    const briefResult = shrinkSecurityBrief(next.security_brief);
    if (briefResult.shrunk) {
      next.security_brief = briefResult.brief;
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
