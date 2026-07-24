/**
 * Unit tests for stack profiling — focused on Expo/React Native detection,
 * where false positives would route projects to the wrong knowledge pack.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { looksLikeExpoOrReactNativeApp, profileProject, type ExpoSignalInput } from "./filesystem.js";
import { recommendPackIds } from "../knowledge/packs/registry.js";

const fixturesDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../fixtures");

const noSignals: ExpoSignalInput = {
  dependencyNames: [],
  appJsonContent: null,
  appConfigContent: null,
  hasEasConfig: false,
  hasMetroConfig: false,
  hasReactNativeConfig: false,
  hasNativeProjectDirs: false,
};

describe("looksLikeExpoOrReactNativeApp", () => {
  it("accepts the expo dependency", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({ ...noSignals, dependencyNames: ["expo", "react"] }),
      true,
    );
  });

  it("accepts expo-scoped modules", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({ ...noSignals, dependencyNames: ["expo-secure-store"] }),
      true,
    );
    assert.equal(
      looksLikeExpoOrReactNativeApp({ ...noSignals, dependencyNames: ["@expo/config"] }),
      true,
    );
  });

  it("accepts app.json with an expo config block", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appJsonContent: '{ "expo": { "name": "app" } }',
      }),
      true,
    );
  });

  it("accepts eas.json alone", () => {
    assert.equal(looksLikeExpoOrReactNativeApp({ ...noSignals, hasEasConfig: true }), true);
  });

  it("accepts app.config.* with ExpoConfig-only or expo import", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appConfigContent:
          'import { ExpoConfig } from "expo/config";\nconst config: ExpoConfig = { name: "app" };\nexport default config;',
      }),
      true,
    );
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appConfigContent: 'import "expo";\nexport default { name: "app" };',
      }),
      true,
    );
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appConfigContent: 'export { default } from "expo/config";',
      }),
      true,
    );
  });

  it("rejects app.config.* expo: undefined without a real Expo shape", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appConfigContent: 'module.exports = { name: "exposition-tool", expo: undefined };',
      }),
      false,
    );
  });

  it("rejects a bare app.json without expo config", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appJsonContent: '{ "name": "some-tool", "displayName": "Tool" }',
      }),
      false,
    );
  });

  it("rejects app.config.* that never references expo", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        appConfigContent: "module.exports = { name: 'tool', plugins: [] };",
      }),
      false,
    );
  });

  it("rejects a stray react-native dependency without app evidence", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        dependencyNames: ["react", "react-native", "react-native-web"],
      }),
      false,
    );
  });

  it("accepts React Native without Expo when app evidence exists", () => {
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        dependencyNames: ["react-native"],
        hasMetroConfig: true,
      }),
      true,
    );
    assert.equal(
      looksLikeExpoOrReactNativeApp({
        ...noSignals,
        dependencyNames: ["react-native"],
        hasNativeProjectDirs: true,
      }),
      true,
    );
  });
});

describe("profileProject fixtures", () => {
  it("detects the Expo fixture", async () => {
    const profile = await profileProject(path.join(fixturesDir, "tiny-expo"));
    assert.equal(profile.hasExpo, true);
    assert.ok(profile.likelyStacks.includes("expo"));
  });

  it("does not treat a react-native library with bare app.json as Expo", async () => {
    const profile = await profileProject(path.join(fixturesDir, "rn-lib-no-expo"));
    assert.equal(profile.hasExpo, false);
    assert.ok(!profile.likelyStacks.includes("expo"));
    const packs = recommendPackIds(profile.likelyStacks, profile);
    assert.ok(!packs.includes("expo-rn"), `unexpected expo-rn: ${packs.join(",")}`);
  });

  it("keeps the Next.js fixture free of Expo signals", async () => {
    const profile = await profileProject(path.join(fixturesDir, "tiny-app"));
    assert.equal(profile.hasExpo, false);
    assert.ok(profile.likelyStacks.includes("nextjs"));
  });
});
