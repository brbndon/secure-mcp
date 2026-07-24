/**
 * Structured knowledge-pack items for progressive, stack-aware guidance.
 * Prefer checkable items over essays; keep packs within ~15–25 items.
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
  impact_if_unremediated?: string;
  remediation?: string;
  verification_suggestion?: string;
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
  remediation?: string;
}

export function toItemSummary(item: PackItem): PackItemSummary {
  return {
    id: item.id,
    title: item.title,
    category: item.category,
    severityHint: item.severityHint,
    ...(item.remediation
      ? { remediation: item.remediation.split(";")[0]?.trim() ?? item.remediation }
      : {}),
  };
}
