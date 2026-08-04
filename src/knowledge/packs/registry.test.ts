/**
 * Unit tests for pack routing, batching, and fair multi-pack sampling.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  ABSOLUTE_MAX_ITEMS,
  DEFAULT_MAX_ITEMS,
  MAX_PACKS_PER_REQUEST,
  PACK_IDS,
  chunkPackIds,
  countEligiblePackItems,
  countItemsPerPack,
  filterPackItems,
  focusedProfileForStack,
  getPack,
  packIdsWithCategories,
  recommendPackIds,
  recommendPackPlan,
  uniquePackIds,
} from "./registry.js";
import type { StackFocus } from "../../lib/types.js";
import type { KnowledgePack, PackItem } from "./types.js";

const emptyProfile = {
  hasExpo: false,
  hasMacOS: false,
  hasNextConfig: false,
  hasSwiftFiles: false,
};

function itemIdsFromPack(packId: string, items: PackItem[]): number {
  const pack = getPack(packId as Parameters<typeof getPack>[0]);
  const ids = new Set(pack.items.map((i) => i.id));
  return items.filter((i) => ids.has(i.id)).length;
}

describe("recommendPackPlan", () => {
  it("recommends core+threat-model for unknown stacks", () => {
    const plan = recommendPackPlan([], emptyProfile);
    assert.deepEqual(plan.recommended_packs, ["core", "threat-model"]);
    assert.equal(plan.pack_batches.length, 1);
    assert.deepEqual(plan.pack_batches[0], plan.recommended_packs);
  });

  it("fits Next.js packs in a single batch (≤ max per request)", () => {
    const plan = recommendPackPlan(["nextjs", "typescript"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    assert.ok(plan.recommended_packs.includes("core"));
    assert.ok(plan.recommended_packs.includes("web-next"));
    assert.ok(plan.recommended_packs.includes("auth-web"));
    assert.ok(plan.recommended_packs.includes("web-api"));
    assert.ok(plan.recommended_packs.includes("secrets"));
    assert.ok(!plan.recommended_packs.includes("expo-rn"));
    assert.ok(!plan.recommended_packs.includes("swift-ios"));
    assert.ok(
      plan.recommended_packs.length <= MAX_PACKS_PER_REQUEST,
      `Next packs ${plan.recommended_packs.length} should fit max ${MAX_PACKS_PER_REQUEST}`,
    );
    assert.equal(plan.pack_batches.length, 1);
    assert.deepEqual(plan.pack_batches[0], plan.recommended_packs);
  });

  it("routes Expo without Next or Swift packs", () => {
    const packs = recommendPackIds(["expo", "typescript"] as StackFocus[], {
      ...emptyProfile,
      hasExpo: true,
    });
    assert.ok(packs.includes("expo-rn"));
    assert.ok(packs.includes("core"));
    assert.ok(packs.includes("secrets"));
    assert.ok(!packs.includes("web-next"));
    assert.ok(!packs.includes("swift-ios"));
  });

  it("routes iOS Swift without apple-desktop", () => {
    const packs = recommendPackIds(["swift"] as StackFocus[], {
      ...emptyProfile,
      hasSwiftFiles: true,
    });
    assert.ok(packs.includes("swift-ios"));
    assert.ok(!packs.includes("apple-desktop"));
    assert.ok(!packs.includes("web-next"));
  });

  it("adds apple-desktop for macOS Swift", () => {
    const packs = recommendPackIds(["swift"] as StackFocus[], {
      ...emptyProfile,
      hasSwiftFiles: true,
      hasMacOS: true,
    });
    assert.ok(packs.includes("swift-ios"));
    assert.ok(packs.includes("apple-desktop"));
  });

  it("batches mixed monorepos when recommendations exceed max per request", () => {
    const plan = recommendPackPlan(
      ["nextjs", "swift", "typescript"] as StackFocus[],
      {
        hasNextConfig: true,
        hasExpo: false,
        hasMacOS: true,
        hasSwiftFiles: true,
      },
    );
    // core, secrets, web-next, auth-web, web-api, swift-ios, apple-desktop = 7
    assert.ok(plan.recommended_packs.length > MAX_PACKS_PER_REQUEST);
    assert.ok(plan.pack_batches.length >= 2);
    for (const batch of plan.pack_batches) {
      assert.ok(
        batch.length <= MAX_PACKS_PER_REQUEST,
        `batch too large: ${batch.join(",")}`,
      );
    }
    const flattened = plan.pack_batches.flat();
    assert.deepEqual(flattened, plan.recommended_packs);
  });

  it("keeps core and secrets early in priority order", () => {
    const packs = recommendPackIds(["nextjs"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    assert.equal(packs[0], "core");
    assert.equal(packs[1], "secrets");
  });
});

describe("chunkPackIds", () => {
  it("returns empty for empty input", () => {
    assert.deepEqual(chunkPackIds([]), []);
  });

  it("chunks at the requested size", () => {
    const packs = [
      "core",
      "secrets",
      "web-next",
      "auth-web",
      "web-api",
      "swift-ios",
      "apple-desktop",
    ] as const;
    const batches = chunkPackIds([...packs], 3);
    assert.equal(batches.length, 3);
    assert.deepEqual(batches[0], ["core", "secrets", "web-next"]);
    assert.deepEqual(batches[2], ["apple-desktop"]);
  });
});

describe("filterPackItems fair sampling", () => {
  it("covers every Next pack under DEFAULT_MAX_ITEMS", () => {
    const plan = recommendPackPlan(["nextjs", "typescript"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const items = filterPackItems(packs, { maxItems: DEFAULT_MAX_ITEMS });
    assert.ok(items.length <= DEFAULT_MAX_ITEMS);
    for (const id of plan.recommended_packs) {
      assert.ok(
        itemIdsFromPack(id, items) >= 1,
        `expected ≥1 item from ${id}, got 0 (total ${items.length})`,
      );
    }
  });

  it("includes expo-rn under DEFAULT_MAX_ITEMS (not only core/secrets)", () => {
    const plan = recommendPackPlan(["expo", "typescript"] as StackFocus[], {
      ...emptyProfile,
      hasExpo: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const items = filterPackItems(packs, { maxItems: DEFAULT_MAX_ITEMS });
    assert.ok(itemIdsFromPack("expo-rn", items) >= 1, "expo-rn starved");
    assert.ok(itemIdsFromPack("core", items) >= 1);
    assert.ok(itemIdsFromPack("secrets", items) >= 1);
  });

  it("still includes stack packs at maxItems=20 (starvation regression)", () => {
    const plan = recommendPackPlan(["nextjs"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const items = filterPackItems(packs, { maxItems: 20 });
    assert.ok(itemIdsFromPack("web-next", items) >= 1);
    assert.ok(itemIdsFromPack("auth-web", items) >= 1);
    assert.ok(itemIdsFromPack("web-api", items) >= 1);
  });

  it("returns full Next recommendation under ABSOLUTE_MAX_ITEMS", () => {
    const plan = recommendPackPlan(["nextjs"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const total = packs.reduce((n, p) => n + p.items.length, 0);
    const items = filterPackItems(packs, { maxItems: ABSOLUTE_MAX_ITEMS });
    assert.equal(items.length, total);
    assert.ok(total <= ABSOLUTE_MAX_ITEMS, `Next total ${total} should fit absolute max`);
  });

  it("preserves single-pack order for the first N items", () => {
    const pack = getPack("core");
    const items = filterPackItems([pack], { maxItems: 3 });
    assert.deepEqual(
      items.map((i) => i.id),
      pack.items.slice(0, 3).map((i) => i.id),
    );
  });

  it("returns empty when maxItems is 0", () => {
    assert.deepEqual(filterPackItems([getPack("core")], { maxItems: 0 }), []);
  });

  it("respects category filters while round-robining", () => {
    const packs = [getPack("core"), getPack("secrets"), getPack("web-next")];
    const items = filterPackItems(packs, {
      maxItems: DEFAULT_MAX_ITEMS,
      categories: ["secrets"],
    });
    assert.ok(items.length > 0);
    for (const item of items) {
      assert.equal(item.category.toLowerCase(), "secrets");
    }
  });

  it("de-dupes shared item ids across packs", () => {
    const shared: PackItem = {
      id: "SHARED-1",
      title: "Shared",
      description: "dup",
      category: "secrets",
      severityHint: "medium",
      impact_if_unremediated: "test only",
      remediation: "test only",
      verification_suggestion: "test only",
    };
    const a: KnowledgePack = {
      id: "core",
      title: "A",
      description: "a",
      stackTags: [],
      categories: ["secrets"],
      estimatedTokens: 1,
      items: [shared, { ...shared, id: "A-ONLY", title: "A only" }],
    };
    const b: KnowledgePack = {
      id: "secrets",
      title: "B",
      description: "b",
      stackTags: [],
      categories: ["secrets"],
      estimatedTokens: 1,
      items: [shared, { ...shared, id: "B-ONLY", title: "B only" }],
    };
    const items = filterPackItems([a, b], { maxItems: 10 });
    const ids = items.map((i) => i.id);
    assert.equal(ids.filter((id) => id === "SHARED-1").length, 1);
    assert.ok(ids.includes("A-ONLY"));
    assert.ok(ids.includes("B-ONLY"));
  });
});

describe("pack item contract", () => {
  it("fills the required remediation narrative on every item", () => {
    for (const packId of PACK_IDS) {
      const pack = getPack(packId);
      for (const item of pack.items) {
        for (const field of [
          "title",
          "description",
          "category",
          "severityHint",
          "impact_if_unremediated",
          "remediation",
          "verification_suggestion",
        ] as const) {
          const value = item[field];
          assert.ok(
            typeof value === "string" && value.trim().length > 0,
            `${packId}/${item.id} missing ${field}`,
          );
        }
      }
    }
  });

  it("declares every category its items use and keeps ids unique", () => {
    for (const packId of PACK_IDS) {
      const pack = getPack(packId);
      const declared = new Set(pack.categories.map((c) => c.toLowerCase()));
      const ids = new Set<string>();
      for (const item of pack.items) {
        assert.ok(
          declared.has(item.category.toLowerCase()),
          `${packId} does not declare category ${item.category} (item ${item.id})`,
        );
        assert.ok(!ids.has(item.id), `${packId} has duplicate item id ${item.id}`);
        ids.add(item.id);
      }
    }
  });

  /**
   * Size band, not a target: packs must be substantial, but a full multi-pack
   * recommendation still has to fit ABSOLUTE_MAX_ITEMS in one tool call.
   */
  it("keeps every pack inside the per-pack size band", () => {
    for (const packId of PACK_IDS) {
      const count = getPack(packId).items.length;
      assert.ok(count >= 8, `${packId} has only ${count} items`);
      assert.ok(count <= 15, `${packId} has ${count} items — trim to keep multi-pack loads lean`);
    }
  });

  it("keeps each routed recommendation within ABSOLUTE_MAX_ITEMS", () => {
    const scenarios: Array<{ stacks: StackFocus[]; profile: typeof emptyProfile }> = [
      { stacks: [], profile: emptyProfile },
      { stacks: ["typescript"], profile: emptyProfile },
      { stacks: ["nextjs", "typescript"], profile: { ...emptyProfile, hasNextConfig: true } },
      { stacks: ["expo", "typescript"], profile: { ...emptyProfile, hasExpo: true } },
      {
        stacks: ["swift"],
        profile: { ...emptyProfile, hasSwiftFiles: true, hasMacOS: true },
      },
    ];
    for (const { stacks, profile } of scenarios) {
      const packs = recommendPackIds(stacks, profile);
      const total = packs.reduce((n, id) => n + getPack(id).items.length, 0);
      assert.ok(
        total <= ABSOLUTE_MAX_ITEMS,
        `${packs.join(",")} total ${total} exceeds ${ABSOLUTE_MAX_ITEMS}`,
      );
    }
  });
});

describe("stackTags match routing", () => {
  const stackDefiningTags: Array<{
    tag: string;
    stacks: StackFocus[];
    profile: typeof emptyProfile;
  }> = [
    { tag: "expo", stacks: ["expo"], profile: { ...emptyProfile, hasExpo: true } },
    { tag: "nextjs", stacks: ["nextjs"], profile: { ...emptyProfile, hasNextConfig: true } },
  ];

  it("only tags a stack when the router recommends the pack for it", () => {
    for (const { tag, stacks, profile } of stackDefiningTags) {
      const routed = new Set(recommendPackIds(stacks, profile));
      for (const packId of PACK_IDS) {
        if (!getPack(packId).stackTags.includes(tag)) continue;
        assert.ok(
          routed.has(packId),
          `${packId} claims stackTag "${tag}" but routing for ${tag} returns ${[...routed].join(",")}`,
        );
      }
    }
  });
});

describe("countEligiblePackItems", () => {
  it("counts unique items available before the maxItems budget", () => {
    const packs = [getPack("core"), getPack("secrets")];
    const total = countEligiblePackItems(packs);
    assert.ok(total > 0);
    assert.equal(total, filterPackItems(packs, { maxItems: ABSOLUTE_MAX_ITEMS }).length);
  });

  it("matches the returned count under a category filter (no false truncation)", () => {
    const plan = recommendPackPlan(["nextjs"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const categories = ["authentication"];
    const items = filterPackItems(packs, { maxItems: DEFAULT_MAX_ITEMS, categories });
    assert.equal(countEligiblePackItems(packs, categories), items.length);
  });

  it("still reports truncation when maxItems cuts the filtered stream", () => {
    const packs = [getPack("core"), getPack("auth-web")];
    const categories = ["authentication"];
    const items = filterPackItems(packs, { maxItems: 2, categories });
    assert.equal(items.length, 2);
    assert.ok(countEligiblePackItems(packs, categories) > items.length);
  });
});

describe("packIdsWithCategories", () => {
  it("keeps only packs carrying the requested categories", () => {
    const expoPlan = recommendPackIds(["expo"] as StackFocus[], {
      ...emptyProfile,
      hasExpo: true,
    });
    const authPacks = packIdsWithCategories(expoPlan, ["authentication", "authorization"]);
    assert.ok(authPacks.includes("core"));
    assert.ok(authPacks.includes("expo-rn"));
    assert.ok(!authPacks.includes("secrets"), `secrets has no authn items: ${authPacks.join(",")}`);
    assert.ok(!authPacks.includes("auth-web"));
  });
});

describe("uniquePackIds", () => {
  it("dedupes pack ids before sampling and counting", () => {
    assert.deepEqual(uniquePackIds(["core", "core", "secrets", "core"]), ["core", "secrets"]);
    const packs = uniquePackIds(["core", "core", "secrets"]).map((id) => getPack(id));
    const items = filterPackItems(packs, { maxItems: DEFAULT_MAX_ITEMS });
    const counts = countItemsPerPack(items, ["core", "core", "secrets"]);
    assert.deepEqual(Object.keys(counts).sort(), ["core", "secrets"]);
    assert.equal(Object.keys(counts).length, 2);
  });
});

describe("countItemsPerPack", () => {
  it("attributes items to owning packs", () => {
    const plan = recommendPackPlan(["nextjs"] as StackFocus[], {
      ...emptyProfile,
      hasNextConfig: true,
    });
    const packs = plan.recommended_packs.map((id) => getPack(id));
    const items = filterPackItems(packs, { maxItems: DEFAULT_MAX_ITEMS });
    const counts = countItemsPerPack(items, plan.recommended_packs);
    for (const id of plan.recommended_packs) {
      assert.ok(counts[id] >= 1, `count for ${id}`);
    }
  });
});

describe("focusedProfileForStack", () => {
  it("does not re-OR unrelated profile flags", () => {
    const mixed = {
      hasExpo: true,
      hasMacOS: true,
      hasNextConfig: true,
      hasSwiftFiles: true,
    };
    assert.deepEqual(focusedProfileForStack("swift", mixed), {
      hasExpo: false,
      hasMacOS: true,
      hasNextConfig: false,
      hasSwiftFiles: true,
    });
    assert.deepEqual(focusedProfileForStack("nextjs", mixed), {
      hasExpo: false,
      hasMacOS: false,
      hasNextConfig: true,
      hasSwiftFiles: false,
    });
    assert.deepEqual(focusedProfileForStack("common", mixed), {
      hasExpo: false,
      hasMacOS: false,
      hasNextConfig: false,
      hasSwiftFiles: false,
    });
  });

  it("focused swift plan ignores hasNextConfig on profile when only stack is swift", () => {
    const packs = recommendPackIds(
      ["swift"],
      focusedProfileForStack("swift", {
        hasExpo: false,
        hasMacOS: false,
        hasNextConfig: true,
        hasSwiftFiles: true,
      }),
    );
    assert.ok(packs.includes("swift-ios"));
    assert.ok(!packs.includes("web-next"));
  });
});
