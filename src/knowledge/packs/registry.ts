/**
 * Knowledge pack registry and stack-aware routing.
 *
 * Agents should load packs on demand via secure_mcp_get_knowledge_pack —
 * never dump every pack into context by default.
 */

import type { ProjectProfile, StackFocus } from "../../lib/types.js";
import { appleDesktopPack } from "./apple-desktop.js";
import { authWebPack } from "./auth-web.js";
import { corePack } from "./core.js";
import { expoRnPack } from "./expo-rn.js";
import { secretsPack } from "./secrets.js";
import { swiftIosPack } from "./swift-ios.js";
import { threatModelPack } from "./threat-model.js";
import { PACK_IDS, type KnowledgePack, type PackId, type PackItem } from "./types.js";
import { webApiPack } from "./web-api.js";
import { webNextPack } from "./web-next.js";

const PACK_BY_ID: Record<PackId, KnowledgePack> = {
  core: corePack,
  "threat-model": threatModelPack,
  "web-next": webNextPack,
  "web-api": webApiPack,
  "auth-web": authWebPack,
  "swift-ios": swiftIosPack,
  "apple-desktop": appleDesktopPack,
  "expo-rn": expoRnPack,
  secrets: secretsPack,
};

export { PACK_IDS };
export type { KnowledgePack, PackId, PackItem };

/**
 * Max pack ids accepted in a single get_knowledge_pack call.
 * Sized so a typical Next.js recommendation (5) fits in one call;
 * mixed monorepos may need pack_batches (sequential calls).
 */
export const MAX_PACKS_PER_REQUEST = 6;
export const DEFAULT_MAX_ITEMS = 20;
export const ABSOLUTE_MAX_ITEMS = 40;

/** Priority order when building recommendations (lower index = load first). */
const PACK_PRIORITY: readonly PackId[] = [
  "core",
  "secrets",
  "web-next",
  "auth-web",
  "web-api",
  "expo-rn",
  "swift-ios",
  "apple-desktop",
  "threat-model",
];

export function isPackId(value: string): value is PackId {
  return (PACK_IDS as readonly string[]).includes(value);
}

export function getPack(id: PackId): KnowledgePack {
  return PACK_BY_ID[id];
}

export function listPackSummaries(): Array<{
  id: PackId;
  title: string;
  description: string;
  stackTags: string[];
  categories: string[];
  estimatedTokens: number;
  itemCount: number;
}> {
  return PACK_IDS.map((id) => {
    const pack = PACK_BY_ID[id];
    return {
      id: pack.id,
      title: pack.title,
      description: pack.description,
      stackTags: pack.stackTags,
      categories: pack.categories,
      estimatedTokens: pack.estimatedTokens,
      itemCount: pack.items.length,
    };
  });
}

/** Split pack ids into batches that fit MAX_PACKS_PER_REQUEST. */
export function chunkPackIds(
  packs: readonly PackId[],
  maxPerBatch: number = MAX_PACKS_PER_REQUEST,
): PackId[][] {
  if (packs.length === 0) return [];
  const size = Math.max(1, maxPerBatch);
  const batches: PackId[][] = [];
  for (let i = 0; i < packs.length; i += size) {
    batches.push(packs.slice(i, i + size));
  }
  return batches;
}

function sortByPriority(ids: Iterable<PackId>): PackId[] {
  const set = new Set(ids);
  return PACK_PRIORITY.filter((id) => set.has(id));
}

export interface PackRecommendation {
  /** Full ordered recommendation (may exceed one tool call for monorepos). */
  recommended_packs: PackId[];
  /**
   * Batches sized for get_knowledge_pack (≤ MAX_PACKS_PER_REQUEST each).
   * Agents should load batch 0 first (detail=summary), then remaining batches if needed.
   */
  pack_batches: PackId[][];
}

/**
 * Recommend pack ids from detected stacks / profile flags.
 * Mixed monorepos get the union of relevant packs (deduped, priority-ordered).
 */
export function recommendPackIds(
  stacks: StackFocus[],
  profile?: Pick<ProjectProfile, "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles">,
): PackId[] {
  return recommendPackPlan(stacks, profile).recommended_packs;
}

/**
 * Full routing plan: ordered packs plus tool-call batches.
 */
export function recommendPackPlan(
  stacks: StackFocus[],
  profile?: Pick<ProjectProfile, "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles">,
): PackRecommendation {
  const set = new Set<PackId>();
  const stackSet = new Set(stacks);

  const hasNext = stackSet.has("nextjs") || profile?.hasNextConfig === true;
  const hasExpo = stackSet.has("expo") || profile?.hasExpo === true;
  const hasSwift = stackSet.has("swift") || profile?.hasSwiftFiles === true;
  const hasMacOS = profile?.hasMacOS === true;
  const hasTs = stackSet.has("typescript");

  const knownAppStack = hasNext || hasExpo || hasSwift || hasTs;
  if (!knownAppStack) {
    const recommended_packs: PackId[] = ["core", "threat-model"];
    return {
      recommended_packs,
      pack_batches: chunkPackIds(recommended_packs),
    };
  }

  set.add("core");
  set.add("secrets");

  if (hasNext) {
    set.add("web-next");
    set.add("auth-web");
    set.add("web-api");
  } else if (hasTs && !hasExpo) {
    // Generic TS/API without Next or Expo
    set.add("web-api");
    set.add("auth-web");
  }

  if (hasExpo) {
    set.add("expo-rn");
  }

  if (hasSwift) {
    set.add("swift-ios");
    if (hasMacOS) {
      set.add("apple-desktop");
    }
  }

  // Threat-model only for unknown/minimal stacks (architecture phase can still
  // call secure_mcp_build_remediation_threat_model without loading the pack text).
  if (!hasNext && !hasExpo && !hasSwift) {
    set.add("threat-model");
  }

  const recommended_packs = sortByPriority(set);
  return {
    recommended_packs,
    pack_batches: chunkPackIds(recommended_packs),
  };
}

export function filterPackItems(
  packs: KnowledgePack[],
  options: { categories?: string[]; maxItems: number },
): PackItem[] {
  const categorySet =
    options.categories && options.categories.length > 0
      ? new Set(options.categories.map((c) => c.toLowerCase()))
      : null;

  const out: PackItem[] = [];
  const seen = new Set<string>();

  for (const pack of packs) {
    for (const item of pack.items) {
      if (categorySet && !categorySet.has(item.category.toLowerCase())) continue;
      if (seen.has(item.id)) continue;
      seen.add(item.id);
      out.push(item);
      if (out.length >= options.maxItems) return out;
    }
  }
  return out;
}

/** Merge checklist-shaped items from packs (server-side use by category tools). */
export function checklistFromPackIds(ids: PackId[]): PackItem[] {
  return filterPackItems(
    ids.map((id) => PACK_BY_ID[id]),
    { maxItems: ABSOLUTE_MAX_ITEMS },
  );
}
