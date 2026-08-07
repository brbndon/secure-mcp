/**
 * Unit tests for authentication-review routing and heuristics.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { describe, it } from "node:test";
import {
  AUTH_PATTERNS,
  authPackIdsForProfile,
  authPatternAppliesToStack,
  isAuthCandidatePath,
  shouldEmitProfileAuthFinding,
  shouldScanSwiftAuthFile,
} from "./checkAuthentication.js";
import type { StackFocus } from "../lib/types.js";
import { detectWithBudget } from "../lib/filesystem.js";
import { redactedEvidence } from "../lib/redact.js";

function patternById(id: string) {
  const pattern = AUTH_PATTERNS.find((p) => p.id === id);
  assert.ok(pattern, `missing pattern ${id}`);
  return pattern;
}

function matches(id: string, source: string): boolean {
  const pattern = patternById(id);
  pattern.regex.lastIndex = 0;
  return pattern.regex.test(source);
}

describe("authPackIdsForProfile", () => {
  it("omits auth-web for Expo-only projects", () => {
    const packs = authPackIdsForProfile({
      hasExpo: true,
      hasMacOS: false,
      hasNextConfig: false,
      hasSwiftFiles: false,
      likelyStacks: ["common", "typescript", "expo"] as StackFocus[],
    });
    assert.ok(packs.includes("expo-rn"), `expected expo-rn: ${packs.join(",")}`);
    assert.ok(packs.includes("core"));
    assert.ok(!packs.includes("auth-web"), `unexpected auth-web: ${packs.join(",")}`);
    assert.ok(!packs.includes("web-next"));
  });

  it("keeps web auth packs for Next.js projects", () => {
    const packs = authPackIdsForProfile({
      hasExpo: false,
      hasMacOS: false,
      hasNextConfig: true,
      hasSwiftFiles: false,
      likelyStacks: ["common", "typescript", "nextjs"] as StackFocus[],
    });
    assert.ok(packs.includes("auth-web"));
    assert.ok(packs.includes("web-next"));
    assert.ok(!packs.includes("expo-rn"));
  });

  it("drops secrets-only packs that carry no authn/authz items", () => {
    const packs = authPackIdsForProfile({
      hasExpo: false,
      hasMacOS: false,
      hasNextConfig: true,
      hasSwiftFiles: false,
      likelyStacks: ["nextjs"] as StackFocus[],
    });
    assert.ok(!packs.includes("secrets"), `secrets is not an authn pack: ${packs.join(",")}`);
  });

  it("scopes packs exclusively when a stack is forced", () => {
    const mixed = {
      hasExpo: true,
      hasMacOS: true,
      hasNextConfig: true,
      hasSwiftFiles: true,
      likelyStacks: ["common", "typescript", "nextjs", "expo", "swift"] as StackFocus[],
    };
    const swiftOnly = authPackIdsForProfile(mixed, "swift");
    assert.ok(swiftOnly.includes("swift-ios"));
    assert.ok(!swiftOnly.includes("auth-web"));
    assert.ok(!swiftOnly.includes("expo-rn"));
  });
});

describe("authPatternAppliesToStack", () => {
  it("keeps every pattern under auto", () => {
    for (const pattern of AUTH_PATTERNS) {
      assert.equal(authPatternAppliesToStack(pattern.stack, "auto"), true);
    }
  });

  it("excludes Swift patterns from Expo focus and vice versa", () => {
    assert.equal(authPatternAppliesToStack("swift", "expo"), false);
    assert.equal(authPatternAppliesToStack("expo", "swift"), false);
    assert.equal(authPatternAppliesToStack("expo", "expo"), true);
    assert.equal(authPatternAppliesToStack("typescript", "expo"), true);
    assert.equal(authPatternAppliesToStack("nextjs", "expo"), false);
    assert.equal(authPatternAppliesToStack(undefined, "swift"), true);
  });
});

describe("shouldEmitProfileAuthFinding", () => {
  it("emits Expo and Swift blurbs under auto when profile flags are set", () => {
    assert.equal(shouldEmitProfileAuthFinding("expo", true, "auto"), true);
    assert.equal(shouldEmitProfileAuthFinding("swift", true, "auto"), true);
    assert.equal(shouldEmitProfileAuthFinding("nextjs", true, "auto"), true);
  });

  it("suppresses unrelated profile blurbs when a stack is forced", () => {
    assert.equal(shouldEmitProfileAuthFinding("expo", true, "swift"), false);
    assert.equal(shouldEmitProfileAuthFinding("nextjs", true, "expo"), false);
    assert.equal(shouldEmitProfileAuthFinding("swift", true, "expo"), false);
    assert.equal(shouldEmitProfileAuthFinding("expo", true, "expo"), true);
    assert.equal(shouldEmitProfileAuthFinding("swift", true, "swift"), true);
  });

  it("does not emit when the profile signal is absent", () => {
    assert.equal(shouldEmitProfileAuthFinding("expo", false, "auto"), false);
    assert.equal(shouldEmitProfileAuthFinding("swift", false, "swift"), false);
  });
});

describe("isAuthCandidatePath", () => {
  it("keeps auth, token, and explicit mobile storage paths", () => {
    assert.ok(isAuthCandidatePath("src/auth/login.ts"));
    assert.ok(isAuthCandidatePath("src/mmkv/cache.ts"));
    assert.ok(isAuthCandidatePath("src/secure-store/tokens.ts"));
    assert.ok(isAuthCandidatePath("src/lib/AsyncStorage.ts"));
    assert.ok(isAuthCandidatePath("src/lib/async-storage.ts"));
    assert.ok(isAuthCandidatePath("lib/auth.ts"));
  });

  it("excludes bare storage helpers that crowd the scan budget", () => {
    assert.ok(!isAuthCandidatePath("src/lib/storage.ts"));
    assert.ok(!isAuthCandidatePath("src/utils/localStorageHelper.ts"));
    assert.ok(!isAuthCandidatePath("packages/ui/src/hooks/useLocalStorage.ts"));
  });
});

describe("shouldScanSwiftAuthFile", () => {
  it("scans all Swift files when stack is forced to swift", () => {
    assert.equal(
      shouldScanSwiftAuthFile("Sources/DemoApp/InsecureBits.swift", ".swift", "swift"),
      true,
    );
    assert.equal(shouldScanSwiftAuthFile("Sources/DemoApp/SafeBits.swift", ".swift", "swift"), true);
  });

  it("uses path keywords under auto", () => {
    assert.equal(
      shouldScanSwiftAuthFile("Sources/DemoApp/Helpers.swift", ".swift", "auto"),
      false,
    );
    assert.equal(
      shouldScanSwiftAuthFile("Sources/Network/TrustDelegate.swift", ".swift", "auto"),
      true,
    );
    // "InsecureBits" matches the `secur` keyword substring — intentional path signal.
    assert.equal(
      shouldScanSwiftAuthFile("Sources/DemoApp/InsecureBits.swift", ".swift", "auto"),
      true,
    );
  });
});

describe("redactedEvidence", () => {
  it("masks credential-shaped snippets", () => {
    const masked = redactedEvidence('let password = "hunter2-secret"');
    assert.ok(!masked.includes("hunter2-secret"));
    assert.ok(masked.includes("****") || masked.includes("…"));
  });
});

describe("Expo / React Native auth heuristics", () => {
  it("flags tokens written to AsyncStorage or MMKV", () => {
    assert.ok(
      matches(
        "AUTH-RN-INSECURE-TOKEN-STORE",
        'await AsyncStorage.setItem("accessToken", session.token);',
      ),
    );
    assert.ok(
      matches(
        "AUTH-RN-INSECURE-TOKEN-STORE",
        "const storage = new MMKV();\nstorage.set('refreshToken', r);",
      ),
    );
    assert.ok(
      matches(
        "AUTH-RN-INSECURE-TOKEN-STORE",
        'AsyncStorage.setItem("refresh_token", value);',
      ),
    );
  });

  it("ignores AsyncStorage used for preferences and refresh timestamps", () => {
    assert.ok(
      !matches("AUTH-RN-INSECURE-TOKEN-STORE", 'AsyncStorage.setItem("theme", "dark");'),
    );
    assert.ok(
      !matches(
        "AUTH-RN-INSECURE-TOKEN-STORE",
        'AsyncStorage.setItem("lastRefreshAt", iso);',
      ),
    );
    assert.ok(
      !matches(
        "AUTH-RN-INSECURE-TOKEN-STORE",
        'AsyncStorage.setItem("pullToRefreshEnabled", "1");',
      ),
    );
  });

  it("flags credential-shaped EXPO_PUBLIC_ variables only", () => {
    assert.ok(
      matches("AUTH-EXPO-PUBLIC-CREDENTIAL", "process.env.EXPO_PUBLIC_API_SECRET"),
    );
    assert.ok(
      matches("AUTH-EXPO-PUBLIC-CREDENTIAL", "process.env.EXPO_PUBLIC_AUTH_TOKEN"),
    );
    assert.ok(
      matches("AUTH-EXPO-PUBLIC-CREDENTIAL", "process.env.EXPO_PUBLIC_PRIVATE_KEY"),
    );
    assert.ok(!matches("AUTH-EXPO-PUBLIC-CREDENTIAL", "process.env.EXPO_PUBLIC_API_URL"));
    assert.ok(
      !matches(
        "AUTH-EXPO-PUBLIC-CREDENTIAL",
        "process.env.EXPO_PUBLIC_STRIPE_PUBLISHABLE_KEY",
      ),
    );
    assert.ok(
      !matches(
        "AUTH-EXPO-PUBLIC-CREDENTIAL",
        "process.env.EXPO_PUBLIC_GOOGLE_MAPS_API_KEY",
      ),
    );
    assert.ok(
      !matches(
        "AUTH-EXPO-PUBLIC-CREDENTIAL",
        "process.env.EXPO_PUBLIC_FIREBASE_API_KEY",
      ),
    );
    assert.ok(
      !matches(
        "AUTH-EXPO-PUBLIC-CREDENTIAL",
        "process.env.EXPO_PUBLIC_SUPABASE_ANON_KEY",
      ),
    );
    assert.ok(
      !matches(
        "AUTH-EXPO-PUBLIC-CREDENTIAL",
        "process.env.EXPO_PUBLIC_CLERK_PUBLISHABLE_KEY",
      ),
    );
    assert.ok(!matches("AUTH-EXPO-PUBLIC-CREDENTIAL", "process.env.EXPO_PUBLIC_API_KEY"));
  });

  it("keeps EXPO_PUBLIC_ detection linear on adversarial input", () => {
    const pattern = patternById("AUTH-EXPO-PUBLIC-CREDENTIAL");
    // Thousands of long candidate names that never resolve to a credential
    // suffix: the tempered name token is capped at 64 chars, so each candidate
    // costs a bounded amount of work and real hits are still found.
    const adversarial = ("process.env.EXPO_PUBLIC_" + "A".repeat(300) + "\n").repeat(1_000);
    const start = performance.now();
    const longNameHits = detectWithBudget(pattern.regex, adversarial);
    const longNameMs = performance.now() - start;
    assert.equal(longNameHits.length, 0);
    assert.ok(longNameMs < 1_500, `EXPO detector took ${longNameMs.toFixed(0)}ms on long names`);

    const mixed = adversarial + "process.env.EXPO_PUBLIC_API_SECRET\n";
    const startMixed = performance.now();
    const mixedHits = detectWithBudget(pattern.regex, mixed);
    const mixedMs = performance.now() - startMixed;
    assert.ok(mixedHits.some((hit) => hit.match.includes("API_SECRET")));
    assert.ok(mixedMs < 1_500, `EXPO detector took ${mixedMs.toFixed(0)}ms on mixed input`);
  });

  it("never matches names longer than the bounded identifier token", () => {
    const pattern = patternById("AUTH-EXPO-PUBLIC-CREDENTIAL");
    const longName = `EXPO_PUBLIC_${"A".repeat(80)}SECRET`;
    assert.equal(detectWithBudget(pattern.regex, longName).length, 0);
    const boundaryName = `EXPO_PUBLIC_${"A".repeat(64)}SECRET`;
    assert.equal(detectWithBudget(pattern.regex, boundaryName).length, 1);
  });

  it("notes SecureStore writes without access-control options only", () => {
    assert.ok(
      matches("AUTH-RN-SECURESTORE-WEAK-ACCESS", 'SecureStore.setItemAsync("token", value)'),
    );
    assert.ok(
      !matches(
        "AUTH-RN-SECURESTORE-WEAK-ACCESS",
        'SecureStore.setItemAsync("token", value, { keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY })',
      ),
    );
    assert.ok(
      !matches(
        "AUTH-RN-SECURESTORE-WEAK-ACCESS",
        'SecureStore.setItemAsync("token", value, { requireAuthentication: true })',
      ),
    );
    assert.ok(
      !matches(
        "AUTH-RN-SECURESTORE-WEAK-ACCESS",
        `SecureStore.setItemAsync("token", value, {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
})`,
      ),
    );
  });
});
