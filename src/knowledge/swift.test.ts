/**
 * Unit tests for Swift / Apple platform discovery heuristics.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import {
  isSwiftSensitivePath,
  SWIFT_AUTH_PATTERNS,
  SWIFT_CONFIG_PATTERNS,
  SWIFT_CRYPTO_PATTERNS,
  SWIFT_INJECTION_PATTERNS,
  SWIFT_PATTERNS,
  SWIFT_SECRETS_PATTERNS,
} from "../knowledge/swift.js";
import { profileProject } from "../lib/filesystem.js";
import { recommendPackIds } from "../knowledge/packs/registry.js";
import { AUTH_PATTERNS, authPatternAppliesToStack } from "../tools/checkAuthentication.js";

const fixturesDir = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  "../../fixtures",
);
const tinySwift = path.join(fixturesDir, "tiny-swift");

function matchIds(patterns: { id: string; regex: RegExp; filter?: (m: string, c: string) => boolean }[], content: string): string[] {
  const hits: string[] = [];
  for (const p of patterns) {
    p.regex.lastIndex = 0;
    let match: RegExpExecArray | null;
    while ((match = p.regex.exec(content)) !== null) {
      if (p.filter && !p.filter(match[0], content)) continue;
      hits.push(p.id);
      break;
    }
  }
  return hits;
}

describe("Swift pattern categories", () => {
  it("keeps stable pattern ids across category arrays", () => {
    const ids = SWIFT_PATTERNS.map((p) => p.id);
    assert.ok(ids.includes("SWIFT-USERDEFAULTS-TOKEN"));
    assert.ok(ids.includes("SWIFT-ATS-ARBITRARY"));
    assert.ok(ids.includes("SWIFT-WEBVIEW-HANDLER"));
    assert.ok(ids.includes("SWIFT-KEYCHAIN-ALWAYS"));
    assert.ok(ids.includes("SWIFT-TRUST-DISABLE"));
    assert.equal(new Set(ids).size, ids.length, "SWIFT_PATTERNS must be unique by id");
  });

  it("does not put secrets-only patterns into the injection array", () => {
    const inj = new Set(SWIFT_INJECTION_PATTERNS.map((p) => p.id));
    assert.ok(!inj.has("SWIFT-HARDCODED-PASSWORD"));
    assert.ok(!inj.has("SWIFT-PASTEBOARD-SECRET"));
    assert.ok(!inj.has("SWIFT-PRINT-SENSITIVE"));
    assert.ok(inj.has("SWIFT-WEBVIEW-HANDLER"));
    assert.ok(inj.has("SWIFT-PROCESS-SHELL"));
  });

  it("keeps storage sinks in auth only (no auth↔secrets duplicates)", () => {
    const sec = new Set(SWIFT_SECRETS_PATTERNS.map((p) => p.id));
    const auth = new Set(SWIFT_AUTH_PATTERNS.map((p) => p.id));
    assert.ok(auth.has("SWIFT-USERDEFAULTS-TOKEN"));
    assert.ok(auth.has("SWIFT-KEYCHAIN-ALWAYS"));
    assert.ok(auth.has("SWIFT-SUITE-TOKEN"));
    assert.ok(!sec.has("SWIFT-USERDEFAULTS-TOKEN"));
    assert.ok(!sec.has("SWIFT-KEYCHAIN-ALWAYS"));
    assert.ok(!sec.has("SWIFT-SUITE-TOKEN"));
    assert.ok(sec.has("SWIFT-HARDCODED-PASSWORD"));
    assert.ok(sec.has("SWIFT-PASTEBOARD-SECRET"));
  });

  it("wires auth patterns under stack=swift only", () => {
    const swiftAuth = AUTH_PATTERNS.filter((p) => p.stack === "swift");
    assert.ok(swiftAuth.length >= 4);
    assert.equal(authPatternAppliesToStack("swift", "swift"), true);
    assert.equal(authPatternAppliesToStack("swift", "nextjs"), false);
    assert.equal(authPatternAppliesToStack("expo", "swift"), false);
  });
});

describe("Swift fixture hits and non-hits", () => {
  it("profiles tiny-swift as swift and recommends swift-ios", async () => {
    const profile = await profileProject(tinySwift);
    assert.equal(profile.hasSwiftFiles, true);
    assert.equal(profile.hasPackageSwift, true);
    assert.ok(profile.likelyStacks.includes("swift"));
    const packs = recommendPackIds(["swift"], profile);
    assert.ok(packs.includes("swift-ios"));
    assert.ok(!packs.includes("web-next"));
  });

  it("fires high-signal patterns on InsecureBits.swift", async () => {
    const content = await fs.readFile(
      path.join(tinySwift, "Sources/DemoApp/InsecureBits.swift"),
      "utf8",
    );
    const authHits = matchIds(SWIFT_AUTH_PATTERNS, content);
    const injHits = matchIds(SWIFT_INJECTION_PATTERNS, content);
    const secHits = matchIds(SWIFT_SECRETS_PATTERNS, content);
    const cryptoHits = matchIds(SWIFT_CRYPTO_PATTERNS, content);
    const configHits = matchIds(SWIFT_CONFIG_PATTERNS, content);

    assert.ok(authHits.includes("SWIFT-USERDEFAULTS-TOKEN"));
    assert.ok(authHits.includes("SWIFT-KEYCHAIN-ALWAYS"));
    assert.ok(authHits.includes("SWIFT-TRUST-DISABLE"));
    assert.ok(authHits.includes("SWIFT-SUITE-TOKEN"));

    assert.ok(injHits.includes("SWIFT-WEBVIEW-HANDLER"));
    assert.ok(injHits.includes("SWIFT-DEEP-LINK-HANDLER"));
    assert.ok(injHits.includes("SWIFT-EVAL-JS"));
    assert.ok(injHits.includes("SWIFT-PROCESS-SHELL"));

    assert.ok(secHits.includes("SWIFT-PASTEBOARD-SECRET"));
    assert.ok(secHits.includes("SWIFT-PRINT-SENSITIVE"));
    assert.ok(secHits.includes("SWIFT-HARDCODED-PASSWORD"));

    assert.ok(cryptoHits.includes("SWIFT-WEAK-HASH"));
    assert.ok(configHits.includes("SWIFT-HTTP-URL"));
  });

  it("does not flag trust handlers that evaluate before useCredential", () => {
    const safe = `
func urlSession(_ session: URLSession, didReceive challenge: URLAuthenticationChallenge,
  completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
  if let trust = challenge.protectionSpace.serverTrust,
     SecTrustEvaluateWithError(trust, nil) {
    completionHandler(.useCredential, URLCredential(trust: trust))
  }
}`;
    const hits = matchIds(SWIFT_AUTH_PATTERNS, safe);
    assert.ok(!hits.includes("SWIFT-TRUST-DISABLE"));
  });

  it("does not fire noisy patterns on SafeBits.swift", async () => {
    const content = await fs.readFile(
      path.join(tinySwift, "Sources/DemoApp/SafeBits.swift"),
      "utf8",
    );
    const authHits = matchIds(SWIFT_AUTH_PATTERNS, content);
    const injHits = matchIds(SWIFT_INJECTION_PATTERNS, content);
    const secHits = matchIds(SWIFT_SECRETS_PATTERNS, content);
    const cryptoHits = matchIds(SWIFT_CRYPTO_PATTERNS, content);
    const configHits = matchIds(SWIFT_CONFIG_PATTERNS, content);

    assert.deepEqual(authHits, []);
    assert.deepEqual(injHits, []);
    assert.deepEqual(secHits, []);
    assert.deepEqual(cryptoHits, []);
    assert.deepEqual(configHits, []);
  });

  it("detects ATS exception keys in Info.plist", async () => {
    const content = await fs.readFile(path.join(tinySwift, "Config/Info.plist"), "utf8");
    const hits = matchIds(SWIFT_CONFIG_PATTERNS, content);
    assert.ok(hits.includes("SWIFT-ATS-ARBITRARY"));
    assert.ok(hits.includes("SWIFT-ATS-EXCEPTION"));
  });

  it("recognizes sensitive Apple config paths", () => {
    assert.equal(isSwiftSensitivePath("Config/Info.plist"), true);
    assert.equal(isSwiftSensitivePath("App/GoogleService-Info.plist"), true);
    assert.equal(isSwiftSensitivePath("Demo.entitlements"), true);
    assert.equal(isSwiftSensitivePath("Sources/DemoApp/SafeBits.swift"), false);
  });

  it("skips documentation-style http URLs", () => {
    const hits = matchIds(SWIFT_CONFIG_PATTERNS, 'let docs = "http://example.com/guide"');
    assert.ok(!hits.includes("SWIFT-HTTP-URL"));
    const real = matchIds(
      SWIFT_CONFIG_PATTERNS,
      'let api = "http://api.internal.example.net/v1/session"',
    );
    assert.ok(real.includes("SWIFT-HTTP-URL"));
  });
});
