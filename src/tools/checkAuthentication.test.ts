/**
 * Unit tests for authentication-review routing and heuristics.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { describe, it } from "node:test";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";
import {
  AUTH_PATTERNS,
  appliedAuthPackIds,
  authCandidatePriority,
  authDetectorFamily,
  authPackIdsForProfile,
  authPatternAppliesToStack,
  isAuthCandidatePath,
  shouldEmitProfileAuthFinding,
  shouldScanObjectLevelAuthz,
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

describe("appliedAuthPackIds", () => {
  it("maps evaluated families to content-true packs without inventing consulted-only ids", () => {
    assert.deepEqual(appliedAuthPackIds(["expo-rn.profile-auth-storage"]), ["expo-rn"]);
    assert.deepEqual(
      appliedAuthPackIds(["core.authentication", "web-next.authentication", "web-next.profile-auth-boundary"]),
      ["core", "web-next"],
    );
    assert.deepEqual(appliedAuthPackIds(["auth-web.authentication"]), []);
  });
});

describe("authPatternAppliesToStack", () => {
  it("keeps every pattern under auto", () => {
    for (const pattern of AUTH_PATTERNS) {
      assert.equal(authPatternAppliesToStack(pattern.stack, "auto"), true);
    }
  });

  it("gates auto mode by detected stacks so Next families stay off Expo roots", () => {
    assert.equal(authPatternAppliesToStack("nextjs", "auto", ["expo", "typescript"]), false);
    assert.equal(authPatternAppliesToStack("expo", "auto", ["expo", "typescript"]), true);
    assert.equal(authPatternAppliesToStack("swift", "auto", ["swift"]), true);
    assert.equal(authPatternAppliesToStack("nextjs", "auto", ["swift"]), false);
    assert.equal(authPatternAppliesToStack("typescript", "auto", ["expo"]), true);
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

  it("includes identifier-bearing web handlers so object-level authz is scanned", () => {
    assert.ok(isAuthCandidatePath("app/api/users/[id]/route.ts"));
    assert.ok(!isAuthCandidatePath("app/user/[id].tsx"));
  });
});

describe("authCandidatePriority", () => {
  it("ranks auth-named files above authz-only web handlers in the scan budget", () => {
    assert.equal(authCandidatePriority("lib/auth.ts"), 0);
    assert.equal(authCandidatePriority("app/api/auth/session/route.ts"), 0);
    assert.equal(authCandidatePriority("app/api/users/[id]/route.ts"), 2);
    assert.equal(authCandidatePriority("app/api/account/route.ts"), 2);
    assert.ok(authCandidatePriority("lib/auth.ts") < authCandidatePriority("app/api/users/[id]/route.ts"));
  });
});

describe("shouldScanObjectLevelAuthz", () => {
  it("runs on Next/TS and auto-with-web, not forced Expo or Swift", () => {
    assert.equal(shouldScanObjectLevelAuthz("nextjs"), true);
    assert.equal(shouldScanObjectLevelAuthz("typescript"), true);
    assert.equal(shouldScanObjectLevelAuthz("auto", ["nextjs"]), true);
    assert.equal(shouldScanObjectLevelAuthz("expo"), false);
    assert.equal(shouldScanObjectLevelAuthz("swift"), false);
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

describe("object-level authorization candidates", () => {
  async function withNextHandler(
    source: string,
    run: (client: Client, root: string) => Promise<void>,
  ): Promise<void> {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-authz-auth-"));
    const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
    const server = createServer({
      name: "secure-mcp-test",
      version: "test",
      defaultMaxFiles: 40,
      maxFileBytes: 8192,
      maxDepth: 12,
    });
    const client = new Client({ name: "secure-mcp-test-client", version: "test" });
    try {
      await fs.writeFile(
        path.join(root, "package.json"),
        JSON.stringify({ name: "authz-auth", dependencies: { next: "15.0.0" } }),
        "utf8",
      );
      await fs.writeFile(path.join(root, "next.config.js"), "module.exports = {};\n", "utf8");
      await fs.mkdir(path.join(root, "app", "api", "users", "[id]"), { recursive: true });
      await fs.writeFile(path.join(root, "app", "api", "users", "[id]", "route.ts"), source, "utf8");
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      await run(client, root);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  }

  it("emits a needs_review core.authorization candidate when no owner predicate is present", async () => {
    await withNextHandler(
      `export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const { id } = params;
  return Response.json({ id, owned: true });
}
`,
      async (client, root) => {
        const result = await client.callTool({
          name: "secure_mcp_check_authentication",
          arguments: { project_root: root, stack: "nextjs", response_format: "json" },
        });
        assert.equal(result.isError, undefined);
        const data = result.structuredContent as {
          findings: Array<{
            rule_family?: string;
            disposition?: string;
            file?: string;
            source?: string;
            category?: string;
          }>;
        };
        const idor = data.findings.find((finding) => finding.rule_family === "core.authorization");
        assert.ok(idor, "expected core.authorization candidate");
        assert.equal(idor.disposition, "needs_review");
        assert.equal(idor.category, "authorization");
        assert.equal(idor.file, "app/api/users/[id]/route.ts");
        assert.equal(idor.source, "authz:app/api/users/[id]/route.ts");
      },
    );
  });

  it("does not emit an IDOR candidate when an owner predicate is present", async () => {
    await withNextHandler(
      `export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  const user = await db.user.findFirst({ where: { id: params.id, userId: session.user.id } });
  return Response.json(user);
}
`,
      async (client, root) => {
        const result = await client.callTool({
          name: "secure_mcp_check_authentication",
          arguments: { project_root: root, stack: "nextjs", response_format: "json" },
        });
        assert.equal(result.isError, undefined);
        const data = result.structuredContent as {
          findings: Array<{ rule_family?: string; file?: string }>;
        };
        assert.ok(
          !data.findings.some((finding) => finding.rule_family === "core.authorization"),
          "owner predicate must not produce an IDOR candidate",
        );
      },
    );
  });

  it("does not emit web IDOR candidates for a forced Expo stack", async () => {
    await withNextHandler(
      `export async function GET(_req: Request, { params }: { params: { id: string } }) {
  return Response.json({ id: params.id });
}
`,
      async (client, root) => {
        const result = await client.callTool({
          name: "secure_mcp_check_authentication",
          arguments: { project_root: root, stack: "expo", response_format: "json" },
        });
        assert.equal(result.isError, undefined);
        const data = result.structuredContent as {
          findings: Array<{ rule_family?: string }>;
        };
        assert.ok(!data.findings.some((finding) => finding.rule_family === "core.authorization"));
      },
    );
  });
});
