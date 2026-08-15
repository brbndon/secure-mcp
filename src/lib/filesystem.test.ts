/**
 * Unit tests for stack profiling — focused on Expo/React Native detection,
 * where false positives would route projects to the wrong knowledge pack.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  looksLikeExpoOrReactNativeApp,
  profileProject,
  readProjectFile,
  type ExpoSignalInput,
} from "./filesystem.js";
import { recommendPackIds } from "../knowledge/packs/registry.js";
import { promises as fs } from "node:fs";
import os from "node:os";

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

  it("does not treat package.json alone as TypeScript or app/ as Next.js", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-not-next-"));
    try {
      await fs.mkdir(path.join(root, "app"), { recursive: true });
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "rails-frontend-assets", dependencies: {} }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "app", "readme.txt"), "not next\n", "utf8");
      const profile = await profileProject(root);
      assert.equal(profile.hasPackageJson, true);
      assert.equal(profile.hasTypeScriptFiles, false);
      assert.ok(!profile.likelyStacks.includes("typescript"));
      assert.ok(!profile.likelyStacks.includes("nextjs"));
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("detects Next.js from a next dependency without next.config", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-next-dep-"));
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      const profile = await profileProject(root);
      assert.ok(profile.likelyStacks.includes("nextjs"));
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("claims the TypeScript stack for a plain-JS service (package.json + .js files)", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-js-service-"));
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "js-service", dependencies: { express: "4.19.2" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "server.js"), "const express = require('express');\n", "utf8");
      const profile = await profileProject(root);
      assert.equal(profile.hasTypeScriptFiles, true);
      assert.ok(profile.likelyStacks.includes("typescript"));
      assert.ok(!profile.likelyStacks.includes("nextjs"));
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("honors focus_paths during language sampling", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-focus-"));
    try {
      await fs.mkdir(path.join(root, "mobile"), { recursive: true });
      await fs.mkdir(path.join(root, "web"), { recursive: true });
      await fs.writeFile(path.join(root, "mobile", "app.swift"), "import SwiftUI\n", "utf8");
      await fs.writeFile(path.join(root, "web", "page.tsx"), "export default function Page() {}\n", "utf8");
      // Root still has Next config — config probes are global.
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {}\n", "utf8");

      const focused = await profileProject(root, { focusPrefixes: ["mobile"] });
      assert.equal(focused.hasSwiftFiles, true);
      // Sample walk is focus-scoped; pure TS under web/ should not drive TS sampling.
      // hasTypeScriptFiles may still be true if package.json/tsconfig exist; here they do not.
      assert.equal(focused.hasTypeScriptFiles, false);
      assert.ok(focused.likelyStacks.includes("swift"));
      assert.ok(focused.hasNextConfig);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("bounds the top-level preview while preserving root project signals", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-top-level-"));
    try {
      for (let i = 0; i < 25; i++) {
        await fs.writeFile(path.join(root, `entry-${String(i).padStart(2, "0")}.ts`), "", "utf8");
      }
      await fs.mkdir(path.join(root, "z.xcodeproj"));
      await fs.mkdir(path.join(root, "android"));
      await fs.mkdir(path.join(root, "ios"));

      const profile = await profileProject(root, { maxFiles: 1 });
      assert.equal(profile.topLevelEntries.length, 20);
      assert.equal(profile.topLevelEntriesTruncated, true);
      assert.equal(profile.hasXcodeProject, true);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("does not follow symlinks when reading project files", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-symlink-read-"));
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-outside-read-"));
    try {
      await fs.writeFile(path.join(outside, "secret.ts"), "export const secret = 1;\n", "utf8");
      await fs.symlink(path.join(outside, "secret.ts"), path.join(root, "link.ts"));
      await assert.rejects(() => readProjectFile(root, "link.ts"), /symlink|project root/i);
    } finally {
      await fs.rm(root, { recursive: true, force: true });
      await fs.rm(outside, { recursive: true, force: true });
    }
  });
});
