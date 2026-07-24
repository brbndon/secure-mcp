/**
 * Unit tests for pack routing and batching.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  MAX_PACKS_PER_REQUEST,
  chunkPackIds,
  recommendPackIds,
  recommendPackPlan,
} from "./registry.js";
import type { StackFocus } from "../../lib/types.js";

const emptyProfile = {
  hasExpo: false,
  hasMacOS: false,
  hasNextConfig: false,
  hasSwiftFiles: false,
};

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
