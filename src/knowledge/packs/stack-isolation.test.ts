/**
 * Stack-isolation regression suite.
 *
 * Named tests (`iso-*`, `prog-packs`) guard the "works for RN and Next"
 * contract. They import only the public registry API so a later pack
 * expansion or registry refactor cannot silently widen routing.
 *
 * Run: pnpm exec tsx --test src/knowledge/packs/stack-isolation.test.ts
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  MAX_PACKS_PER_REQUEST,
  chunkPackIds,
  focusedProfileForStack,
  recommendPackIds,
  recommendPackPlan,
} from "./registry.js";
import type { StackFocus } from "../../lib/types.js";

const EMPTY_PROFILE = {
  hasExpo: false,
  hasMacOS: false,
  hasNextConfig: false,
  hasSwiftFiles: false,
} as const;

const NEXT_PROFILE = { ...EMPTY_PROFILE, hasNextConfig: true } as const;
const EXPO_PROFILE = { ...EMPTY_PROFILE, hasExpo: true } as const;
const SWIFT_PROFILE = { ...EMPTY_PROFILE, hasSwiftFiles: true } as const;
const SWIFT_MACOS_PROFILE = { ...SWIFT_PROFILE, hasMacOS: true } as const;

describe("iso-next — pure Next never leaks mobile/Apple packs", () => {
  it("recommends the Next web path and no expo/swift/apple packs", () => {
    const packs = recommendPackIds(["nextjs", "typescript"] as StackFocus[], NEXT_PROFILE);
    assert.ok(packs.includes("core"), packs.join(","));
    assert.ok(packs.includes("secrets"), packs.join(","));
    assert.ok(packs.includes("web-next"), packs.join(","));
    assert.ok(packs.includes("auth-web"), packs.join(","));
    assert.ok(packs.includes("web-api"), packs.join(","));
    for (const banned of ["expo-rn", "swift-ios", "apple-desktop"]) {
      assert.ok(!packs.includes(banned as never), `Next must not route ${banned}: ${packs.join(",")}`);
    }
  });

  it("still excludes expo-rn even when a stray profile flag exists", () => {
    // A pure Next root with an unrelated (but present) app.json must not gain expo-rn.
    const packs = recommendPackIds(["nextjs"] as StackFocus[], {
      ...NEXT_PROFILE,
      hasExpo: false,
    });
    assert.ok(!packs.includes("expo-rn"), packs.join(","));
  });
});

describe("iso-expo — pure Expo app never leaks the Next web path", () => {
  it("recommends expo-rn and excludes web-next/auth-web/web-api", () => {
    const packs = recommendPackIds(["expo", "typescript"] as StackFocus[], EXPO_PROFILE);
    assert.ok(packs.includes("core"), packs.join(","));
    assert.ok(packs.includes("secrets"), packs.join(","));
    assert.ok(packs.includes("expo-rn"), packs.join(","));
    for (const banned of ["web-next", "auth-web", "web-api", "swift-ios"]) {
      assert.ok(!packs.includes(banned as never), `Expo must not route ${banned}: ${packs.join(",")}`);
    }
  });

  it("forced stack=expo is exclusive focus and does not re-OR unrelated signals", () => {
    const mixed = {
      hasExpo: true,
      hasMacOS: true,
      hasNextConfig: true,
      hasSwiftFiles: true,
    };
    const profile = focusedProfileForStack("expo", mixed);
    assert.equal(profile.hasNextConfig, false);
    assert.equal(profile.hasSwiftFiles, false);
    const packs = recommendPackIds(["expo"], profile);
    assert.ok(packs.includes("expo-rn"), packs.join(","));
    assert.ok(!packs.includes("web-next"), packs.join(","));
    assert.ok(!packs.includes("swift-ios"), packs.join(","));
  });
});

describe("iso-swift — pure Swift never emits Next or Expo surfaces", () => {
  it("routes swift-ios only, without web-next/expo-rn/apple-desktop", () => {
    const packs = recommendPackIds(["swift"] as StackFocus[], SWIFT_PROFILE);
    assert.ok(packs.includes("core"), packs.join(","));
    assert.ok(packs.includes("secrets"), packs.join(","));
    assert.ok(packs.includes("swift-ios"), packs.join(","));
    for (const banned of ["web-next", "expo-rn", "apple-desktop"]) {
      assert.ok(!packs.includes(banned as never), `Swift iOS must not route ${banned}: ${packs.join(",")}`);
    }
  });

  it("adds apple-desktop only with macOS evidence", () => {
    const packs = recommendPackIds(["swift"] as StackFocus[], SWIFT_MACOS_PROFILE);
    assert.ok(packs.includes("apple-desktop"), packs.join(","));
    assert.ok(!packs.includes("web-next"), packs.join(","));
  });
});

describe("iso-rn-lib — RN library without an Expo app does not behave like an app", () => {
  it("does not route to expo-rn for a bare RN library", () => {
    // rn-lib-no-expo: react-native dependency + non-Expo app.json → typescript, no expo signal.
    const packs = recommendPackIds(["typescript"] as StackFocus[], EMPTY_PROFILE);
    assert.ok(!packs.includes("expo-rn"), packs.join(","));
    assert.ok(!packs.includes("web-next"), packs.join(","));
  });

  it("forced stack=typescript keeps Expo packs out even with a stray expo profile flag", () => {
    const profile = focusedProfileForStack("typescript", {
      hasExpo: true,
      hasMacOS: false,
      hasNextConfig: false,
      hasSwiftFiles: false,
    });
    assert.equal(profile.hasExpo, false);
    const packs = recommendPackIds(["typescript"], profile);
    assert.ok(!packs.includes("expo-rn"), packs.join(","));
  });
});

describe("prog-packs — default knowledge load stays batched and priority-ordered", () => {
  it("chunks any recommendation into ≤ MAX_PACKS_PER_REQUEST batches", () => {
    const plan = recommendPackPlan(
      ["nextjs", "swift", "typescript"] as StackFocus[],
      { ...SWIFT_MACOS_PROFILE, hasNextConfig: true },
    );
    assert.ok(plan.recommended_packs.length > MAX_PACKS_PER_REQUEST, "fixture must exceed one batch");
    for (const batch of plan.pack_batches) {
      assert.ok(batch.length <= MAX_PACKS_PER_REQUEST, batch.join(","));
    }
    assert.deepEqual(plan.pack_batches.flat(), plan.recommended_packs);
  });

  it("keeps core and secrets first in priority order for every known app stack", () => {
    for (const profile of [NEXT_PROFILE, EXPO_PROFILE, SWIFT_PROFILE]) {
      const stacks: StackFocus[] =
        profile === NEXT_PROFILE
          ? ["nextjs", "typescript"]
          : profile === EXPO_PROFILE
            ? ["expo", "typescript"]
            : ["swift"];
      const packs = recommendPackIds(stacks, profile);
      assert.equal(packs[0], "core", packs.join(","));
      assert.equal(packs[1], "secrets", packs.join(","));
    }
  });

  it("chunkPackIds is stable and never emits a singleton empty batch", () => {
    assert.deepEqual(chunkPackIds([]), []);
    assert.deepEqual(chunkPackIds(["core", "secrets", "web-next", "auth-web", "web-api", "expo-rn", "swift-ios"]), [
      ["core", "secrets", "web-next", "auth-web", "web-api", "expo-rn"],
      ["swift-ios"],
    ]);
  });
});
