/**
 * Structured knowledge-pack items for progressive, stack-aware guidance.
 *
 * Prefer checkable items over essays. Pack size is bounded by the multi-pack
 * item budget (ABSOLUTE_MAX_ITEMS): a full recommendation can be five packs, so
 * ~10–13 items per pack keeps a complete load inside one tool call.
 */

import type { Severity } from "../../lib/types.js";

/** Stable pack identifiers (public for agents via get_knowledge_pack). */
export const PACK_IDS = [
  "core",
  "threat-model",
  "web-next",
  "web-api",
  "auth-web",
  "swift-ios",
  "apple-desktop",
  "expo-rn",
  "secrets",
] as const;

export type PackId = (typeof PACK_IDS)[number];

/** Checklist-compatible pack item (extends the historical ChecklistItem shape). */
export interface PackItem {
  id: string;
  title: string;
  description: string;
  category: string;
  severityHint: Severity;
  cwe?: string;
  tags?: string[];
  /** Stacks this item is most relevant to (for filtering / routing hints). */
  stacks?: string[];
  /**
   * Required remediation narrative fields — they mirror the Finding contract so
   * agents can lift pack items straight into a report without inventing copy.
   */
  impact_if_unremediated: string;
  remediation: string;
  verification_suggestion: string;
}

/** Metadata + items for one named knowledge pack. */
export interface KnowledgePack {
  id: PackId;
  title: string;
  description: string;
  /** Stack tags used for discovery (e.g. nextjs, expo, swift, macos). */
  stackTags: string[];
  categories: string[];
  /** Rough JSON token estimate for the full pack (design target, not exact). */
  estimatedTokens: number;
  items: PackItem[];
}

/** Compact row returned when detail=summary. */
export interface PackItemSummary {
  id: string;
  title: string;
  category: string;
  severityHint: Severity;
  /** First clause of the item remediation — enough to triage without full text. */
  remediation: string;
}

export function toItemSummary(item: PackItem): PackItemSummary {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    severityHint: item.severityHint,
    remediation: item.remediation.split(";")[0]?.trim() ?? item.remediation,
  };
}
