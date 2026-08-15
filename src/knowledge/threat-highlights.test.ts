import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  HIGHLIGHT_TEXT_CAP,
  HIGHLIGHT_TOTAL_CAP,
  HIGHLIGHTS_PER_STACK,
  threatHighlightsForStacks,
} from "./threat-highlights.js";

describe("threatHighlightsForStacks", () => {
  it("emits Next-only highlights for a Next stack and never Swift ones", () => {
    const highlights = threatHighlightsForStacks(["nextjs"]);
    assert.ok(highlights.some((item) => item.id === "NEXT-MIDDLEWARE-AUTH"));
    assert.ok(highlights.some((item) => item.id === "NEXT-SERVER-ACTIONS"));
    assert.ok(highlights.some((item) => item.id === "NEXT-CACHE-TENANCY"));
    assert.ok(!highlights.some((item) => item.pack_id === "swift-ios"));
    assert.ok(!highlights.some((item) => item.pack_id === "expo-rn"));
  });

  it("does not invent Next highlights for a Swift-only root", () => {
    const highlights = threatHighlightsForStacks(["swift"]);
    assert.ok(highlights.some((item) => item.pack_id === "swift-ios"));
    assert.ok(!highlights.some((item) => item.stack === "nextjs"));
    assert.ok(!highlights.some((item) => /server action|middleware|cache tag/i.test(item.text)));
    assert.ok(!highlights.some((item) => item.pack_id === "apple-desktop"));
  });

  it("adds apple-desktop highlights only when macOS is signaled", () => {
    const iosOnly = threatHighlightsForStacks(["swift"], { hasMacOS: false });
    const desktop = threatHighlightsForStacks(["swift"], { hasMacOS: true });
    assert.ok(!iosOnly.some((item) => item.pack_id === "apple-desktop"));
    assert.ok(desktop.some((item) => item.pack_id === "apple-desktop"));
  });

  it("keeps Expo highlights off TypeScript-only roots", () => {
    const highlights = threatHighlightsForStacks(["typescript"]);
    assert.ok(!highlights.some((item) => item.pack_id === "expo-rn"));
    assert.ok(!highlights.some((item) => item.pack_id === "web-next"));
    assert.ok(highlights.some((item) => item.pack_id === "auth-web"));
  });

  it("enforces per-stack and total size budgets", () => {
    const highlights = threatHighlightsForStacks(["nextjs", "expo", "swift"], { hasMacOS: true });
    assert.ok(highlights.length <= HIGHLIGHT_TOTAL_CAP);
    const byPack = new Map<string, number>();
    for (const item of highlights) {
      assert.ok(item.text.length <= HIGHLIGHT_TEXT_CAP);
      byPack.set(item.pack_id, (byPack.get(item.pack_id) ?? 0) + 1);
    }
    for (const count of byPack.values()) {
      assert.ok(count <= HIGHLIGHTS_PER_STACK);
    }
  });
});
