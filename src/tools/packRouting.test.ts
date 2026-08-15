/**
 * Cross-tool tests for registry-backed category pack routing.
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { ProjectProfile } from "../lib/types.js";
import { threatModelPackIds } from "./buildRemediationThreatModel.js";
import { authPackIdsForProfile } from "./checkAuthentication.js";
import { secretsPackIdsForStack } from "./reviewSecrets.js";

function profile(likelyStacks: ProjectProfile["likelyStacks"]): ProjectProfile {
  return {
    root: "/tmp/project",
    hasPackageJson: true,
    hasNextConfig: likelyStacks.includes("nextjs"),
    hasTsConfig: true,
    hasPackageSwift: false,
    hasXcodeProject: false,
    hasSwiftFiles: false,
    hasTypeScriptFiles: true,
    hasExpo: false,
    hasMacOS: false,
    likelyStacks,
    topLevelEntries: [],
    topLevelEntriesTruncated: false,
  };
}

describe("category-tool pack routing", () => {
  it("propagates an added Next.js focus through all three category routes", () => {
    const withoutNext = [
      authPackIdsForProfile(profile(["common", "typescript"])),
      secretsPackIdsForStack("typescript"),
      threatModelPackIds(["typescript"]),
    ];
    const withNext = [
      authPackIdsForProfile(profile(["common", "typescript", "nextjs"])),
      secretsPackIdsForStack("nextjs"),
      threatModelPackIds(["typescript", "nextjs"]),
    ];

    for (const packs of withoutNext) assert.ok(!packs.includes("web-next"));
    for (const packs of withNext) {
      assert.ok(packs.includes("core"));
      assert.ok(packs.includes("web-next"));
      assert.ok(!packs.includes("expo-rn"));
      assert.ok(!packs.includes("swift-ios"));
    }
  });

  it("keeps auto secrets routing conservative until detected stacks are supplied", () => {
    assert.deepEqual(secretsPackIdsForStack("auto"), ["core", "secrets"]);
    assert.deepEqual(secretsPackIdsForStack("auto", ["common", "typescript", "expo"]), [
      "core",
      "secrets",
    ]);
    assert.deepEqual(threatModelPackIds(["nextjs", "typescript"]), [
      "threat-model",
      "core",
      "secrets",
      "web-next",
      "auth-web",
      "web-api",
    ]);
    assert.deepEqual(threatModelPackIds(["expo"]), [
      "threat-model",
      "core",
      "secrets",
      "expo-rn",
    ]);
  });
});
