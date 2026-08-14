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
/** Default item budget for get_knowledge_pack (~4 items × 6 packs under fair sampling). */
export const DEFAULT_MAX_ITEMS = 24;
/** Hard cap — large enough for a full Next.js 5-pack load (~49 items). */
export const ABSOLUTE_MAX_ITEMS = 60;

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
    // Honest degrade for unknown/minimal stacks: core + secrets + threat-model.
    // Unknown repos can still leak credentials, so secrets is always in scope;
    // no stack pack is ever claimed without evidence. Architecture adds explicit
    // unsupported/gap notes so agents report a limited generic review, not a full audit.
    const recommended_packs: PackId[] = ["core", "secrets", "threat-model"];
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

/**
 * Select checklist items from one or more packs with a hard maxItems budget.
 *
 * Uses round-robin across packs (request order) so multi-pack loads do not
 * starve later stack packs when core/secrets are listed first. Within each
 * pack, original item order is preserved. Global de-dupe is by item.id.
 */
export function filterPackItems(
  packs: KnowledgePack[],
  options: { categories?: string[]; maxItems: number },
): PackItem[] {
  if (options.maxItems <= 0 || packs.length === 0) return [];

  const categorySet =
    options.categories && options.categories.length > 0
      ? new Set(options.categories.map((c) => c.toLowerCase()))
      : null;

  const queues = packs.map((pack) =>
    pack.items.filter(
      (item) => !categorySet || categorySet.has(item.category.toLowerCase()),
    ),
  );
  const heads = queues.map(() => 0);
  const out: PackItem[] = [];
  const seen = new Set<string>();

  let madeProgress = true;
  while (out.length < options.maxItems && madeProgress) {
    madeProgress = false;
    for (let i = 0; i < queues.length; i++) {
      if (out.length >= options.maxItems) break;
      const queue = queues[i];
      while (heads[i] < queue.length) {
        const item = queue[heads[i]];
        heads[i] += 1;
        if (seen.has(item.id)) continue;
        seen.add(item.id);
        out.push(item);
        madeProgress = true;
        break; // one new item per pack per round
      }
    }
  }

  return out;
}

/**
 * Narrow pack ids to those that actually carry items in the given categories.
 * Category tools use this so consulted_pack_ids reflects the packs behind
 * their routing (e.g. an Expo-only project should not consult auth-web).
 * applied_pack_ids is the subset whose detectors actually evaluated content.
 */
export function packIdsWithCategories(
  ids: readonly PackId[],
  categories: readonly string[],
): PackId[] {
  const wanted = new Set(categories.map((c) => c.toLowerCase()));
  return ids.filter((id) =>
    PACK_BY_ID[id].items.some((item) => wanted.has(item.category.toLowerCase())),
  );
}

type PackRoutingProfile = Pick<
  ProjectProfile,
  "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles"
>;

/**
 * Shared category-tool routing: recommend from stack/profile evidence, apply
 * exclusive forced-stack flags when requested, then narrow to pack content the
 * tool actually uses. The threat-model pack is opt-in for detector tools.
 */
export function recommendCategoryPackIds(
  stacks: readonly StackFocus[],
  categories: readonly string[],
  options: {
    profile?: PackRoutingProfile;
    focusedStack?: StackFocus;
    includeThreatModel?: boolean;
  } = {},
): PackId[] {
  const profile = options.focusedStack
    ? focusedProfileForStack(options.focusedStack, options.profile)
    : options.profile;
  const routed = packIdsWithCategories(recommendPackIds([...stacks], profile), categories);
  return options.includeThreatModel
    ? routed
    : routed.filter((id) => id !== "threat-model");
}

/**
 * Unique items a request could return before the maxItems budget is applied.
 * Lets callers distinguish "cut by max_items" from "narrowed by categories".
 */
export function countEligiblePackItems(
  packs: KnowledgePack[],
  categories?: string[],
): number {
  const categorySet =
    categories && categories.length > 0
      ? new Set(categories.map((c) => c.toLowerCase()))
      : null;
  const ids = new Set<string>();
  for (const pack of packs) {
    for (const item of pack.items) {
      if (categorySet && !categorySet.has(item.category.toLowerCase())) continue;
      ids.add(item.id);
    }
  }
  return ids.size;
}

/** Preserve first-seen order while dropping duplicate pack ids. */
export function uniquePackIds(packIds: readonly PackId[]): PackId[] {
  const seen = new Set<PackId>();
  const out: PackId[] = [];
  for (const id of packIds) {
    if (seen.has(id)) continue;
    seen.add(id);
    out.push(id);
  }
  return out;
}

/**
 * Count how many returned items belong to each pack (by item id membership).
 * Used so agents can see fair multi-pack coverage (or truncation).
 */
export function countItemsPerPack(
  items: ReadonlyArray<{ id: string }>,
  packIds: readonly PackId[],
): Record<PackId, number> {
  const uniqueIds = uniquePackIds(packIds);
  const counts = {} as Record<PackId, number>;
  for (const id of uniqueIds) counts[id] = 0;

  const idToPacks = new Map<string, PackId[]>();
  for (const packId of uniqueIds) {
    for (const item of PACK_BY_ID[packId].items) {
      const list = idToPacks.get(item.id) ?? [];
      list.push(packId);
      idToPacks.set(item.id, list);
    }
  }

  for (const item of items) {
    const owners = idToPacks.get(item.id);
    if (!owners) continue;
    for (const packId of owners) {
      counts[packId] = (counts[packId] ?? 0) + 1;
    }
  }
  return counts;
}

/**
 * Profile flags used only for the given stack focus (exclusive).
 * When architecture forces a stack, do not re-OR unrelated profile signals.
 */
export function focusedProfileForStack(
  stack: StackFocus,
  profile?: Pick<ProjectProfile, "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles">,
): Pick<ProjectProfile, "hasExpo" | "hasMacOS" | "hasNextConfig" | "hasSwiftFiles"> {
  return {
    hasExpo: stack === "expo",
    hasMacOS: stack === "swift" ? profile?.hasMacOS === true : false,
    hasNextConfig: stack === "nextjs",
    hasSwiftFiles: stack === "swift",
  };
}

/** Merge checklist-shaped items from packs (server-side use by category tools). */
export function checklistFromPackIds(ids: PackId[]): PackItem[] {
  return filterPackItems(
    ids.map((id) => PACK_BY_ID[id]),
    { maxItems: ABSOLUTE_MAX_ITEMS },
  );
}
