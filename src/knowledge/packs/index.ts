/**
 * Compatibility barrel for package consumers. Internal lookups should import
 * directly from registry so pack routing continues to have one owner.
 */

export { appleDesktopPack } from "./apple-desktop.js";
export { authWebPack } from "./auth-web.js";
export { corePack } from "./core.js";
export { expoRnPack } from "./expo-rn.js";
export { secretsPack } from "./secrets.js";
export { swiftIosPack } from "./swift-ios.js";
export { threatModelPack } from "./threat-model.js";
export { webApiPack } from "./web-api.js";
export { webNextPack } from "./web-next.js";
export {
  ABSOLUTE_MAX_ITEMS,
  DEFAULT_MAX_ITEMS,
  MAX_PACKS_PER_REQUEST,
  checklistFromPackIds,
  chunkPackIds,
  countEligiblePackItems,
  countItemsPerPack,
  filterPackItems,
  focusedProfileForStack,
  getPack,
  isPackId,
  listPackSummaries,
  packIdsWithCategories,
  recommendCategoryPackIds,
  recommendPackIds,
  recommendPackPlan,
  uniquePackIds,
  PACK_IDS,
} from "./registry.js";
export type { PackRecommendation } from "./registry.js";
export type { KnowledgePack, PackId, PackItem, PackItemSummary } from "./types.js";
export { toItemSummary } from "./types.js";
