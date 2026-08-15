/**
 * Compact, stack-gated threat highlights for architecture prompts.
 * Titles are lifted from existing pack items — not a second knowledge system.
 */

import type { StackFocus } from "../lib/types.js";
import { getPack, type PackId } from "./packs/registry.js";

export interface ThreatHighlight {
  stack: StackFocus | "common";
  pack_id: PackId;
  id: string;
  text: string;
}

export const HIGHLIGHTS_PER_STACK = 3;
export const HIGHLIGHT_TEXT_CAP = 120;
export const HIGHLIGHT_TOTAL_CAP = 10;

interface HighlightSpec {
  stack: StackFocus | "common";
  packId: PackId;
  itemIds: readonly string[];
  when: (stacks: readonly StackFocus[], options: { hasMacOS: boolean }) => boolean;
}

const HIGHLIGHT_SPECS: readonly HighlightSpec[] = [
  {
    stack: "common",
    packId: "core",
    itemIds: ["CMN-AUTHZ-IDOR"],
    when: () => true,
  },
  {
    stack: "common",
    packId: "secrets",
    itemIds: ["SEC-CLIENT-BUNDLE"],
    when: () => true,
  },
  {
    stack: "nextjs",
    packId: "web-next",
    itemIds: ["NEXT-MIDDLEWARE-AUTH", "NEXT-SERVER-ACTIONS", "NEXT-CACHE-TENANCY"],
    when: (stacks) => stacks.includes("nextjs"),
  },
  {
    stack: "typescript",
    packId: "auth-web",
    itemIds: ["AUTHWEB-COOKIE-FLAGS", "AUTHWEB-CSRF"],
    when: (stacks) => stacks.includes("nextjs") || stacks.includes("typescript"),
  },
  {
    stack: "expo",
    packId: "expo-rn",
    itemIds: ["EXPO-SECURE-STORE", "EXPO-PUBLIC-ENV", "EXPO-DEEP-LINKS"],
    when: (stacks) => stacks.includes("expo"),
  },
  {
    stack: "swift",
    packId: "swift-ios",
    itemIds: ["SWIFT-KEYCHAIN", "SWIFT-WEBVIEW", "SWIFT-DEEP-LINKS"],
    when: (stacks) => stacks.includes("swift"),
  },
  {
    stack: "swift",
    packId: "apple-desktop",
    itemIds: ["MAC-ENTITLEMENTS", "MAC-XPC-BOUNDARY"],
    when: (stacks, options) => stacks.includes("swift") && options.hasMacOS,
  },
];

function clipHighlightText(text: string): string {
  if (text.length <= HIGHLIGHT_TEXT_CAP) return text;
  return `${text.slice(0, HIGHLIGHT_TEXT_CAP - 1).trimEnd()}…`;
}

/** Advisory shortlist for the active stacks. Not a finding list. */
export function threatHighlightsForStacks(
  stacks: readonly StackFocus[],
  options: { hasMacOS?: boolean } = {},
): ThreatHighlight[] {
  const hasMacOS = options.hasMacOS === true;
  const out: ThreatHighlight[] = [];
  const takenByPack = new Map<string, number>();
  for (const spec of HIGHLIGHT_SPECS) {
    if (!spec.when(stacks, { hasMacOS })) continue;
    const pack = getPack(spec.packId);
    for (const itemId of spec.itemIds) {
      if (out.length >= HIGHLIGHT_TOTAL_CAP) return out;
      if ((takenByPack.get(spec.packId) ?? 0) >= HIGHLIGHTS_PER_STACK) break;
      const item = pack.items.find((entry) => entry.id === itemId);
      if (!item) continue;
      out.push({
        stack: spec.stack,
        pack_id: spec.packId,
        id: item.id,
        text: clipHighlightText(item.title),
      });
      takenByPack.set(spec.packId, (takenByPack.get(spec.packId) ?? 0) + 1);
    }
  }
  return out;
}
