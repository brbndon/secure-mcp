/**
 * Tool: secure_mcp_get_knowledge_pack
 * On-demand, capped knowledge packs for progressive agent context loading.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { toolError, toolSuccess } from "../lib/filesystem.js";
import {
  ABSOLUTE_MAX_ITEMS,
  DEFAULT_MAX_ITEMS,
  MAX_PACKS_PER_REQUEST,
  PACK_IDS,
  countEligiblePackItems,
  countItemsPerPack,
  uniquePackIds,
  filterPackItems,
  getPack,
  isPackId,
  listPackSummaries,
  type PackId,
} from "../knowledge/packs/registry.js";
import { toItemSummary } from "../knowledge/packs/types.js";

const InputSchema = z
  .object({
    pack_ids: z
      .array(z.string().min(1))
      .min(1)
      .max(MAX_PACKS_PER_REQUEST)
      .describe(
        `Required pack ids to load (max ${MAX_PACKS_PER_REQUEST} per call). Known ids: ${PACK_IDS.join(", ")}. Prefer pack_batches from architecture; do not request all packs.`,
      ),
    categories: z
      .array(z.string().min(1))
      .max(20)
      .optional()
      .describe(
        "Optional category filter (e.g. authentication, secrets). Case-insensitive match on item.category.",
      ),
    max_items: z
      .number()
      .int()
      .min(1)
      .max(ABSOLUTE_MAX_ITEMS)
      .default(DEFAULT_MAX_ITEMS)
      .describe(
        `Cap on returned checklist items across all requested packs (default ${DEFAULT_MAX_ITEMS}, hard max ${ABSOLUTE_MAX_ITEMS}). Items are fair-sampled (round-robin) so stack packs are not starved.`,
      ),
    detail: z
      .enum(["summary", "full"])
      .default("summary")
      .describe(
        "summary (default, low-token): id, title, category, severityHint, one-line remediation. full: complete pack items. Prefer one pack or categories when detail=full on large multi-pack loads.",
      ),
    include_index: z
      .boolean()
      .default(false)
      .describe(
        "If true, include available_packs index (all pack ids/metadata). Default false to keep responses lean — use architecture pack_batches instead.",
      ),
    response_format: z
      .enum(["json", "markdown"])
      .default("json")
      .describe("json for structured agent processing; markdown for human-readable summaries"),
  })
  .strict();

type Input = z.infer<typeof InputSchema>;

export function registerGetKnowledgePack(server: McpServer): void {
  server.registerTool(
    "secure_mcp_get_knowledge_pack",
    {
      title: "Get knowledge pack (on demand)",
      description: `Defensive secure-code-review tool: return stack-aware knowledge pack checklist items on demand.

PURPOSE (defensive only)
- Progressive disclosure: load only packs recommended after architecture / stack detection.
- Keep agent context small — prefer detail=summary first; use full when drafting remediations.
- Multi-pack loads fair-sample items (round-robin) so core/secrets do not crowd out stack packs under max_items.
- Packs are structured checklists (not essays). They guide classification and remediation planning.
- Never frame pack content as offensive targeting guidance.

WHEN TO CALL
1. After secure_mcp_list_project_structure and secure_mcp_analyze_architecture.
2. Prefer pack_batches[0] from architecture (then later batches if needed). Max ${MAX_PACKS_PER_REQUEST} pack_ids per call.
3. Do not request every pack. Category scanners already use heuristics server-side; call this when you need checklist text.
4. Set include_index=true only if you need the global pack catalog (rare).
5. For detail=full on many packs, prefer one pack_id or categories, or raise max_items (hard max ${ABSOLUTE_MAX_ITEMS}).

Args:
  - pack_ids (string[]): Required. Known: ${PACK_IDS.join(", ")}
  - categories (string[]): Optional filter
  - max_items (number): Default ${DEFAULT_MAX_ITEMS}, max ${ABSOLUTE_MAX_ITEMS} (fair-sampled across packs)
  - detail: summary (default) | full
  - include_index (boolean): default false — omit available_packs catalog
  - response_format: json | markdown

Returns:
  applied_pack_ids, items (summary or full), items_per_pack coverage counts, optional available_packs if include_index, and notes.`,
      inputSchema: InputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params: Input) => {
      try {
        const invalid = params.pack_ids.filter((id) => !isPackId(id));
        if (invalid.length > 0) {
          return toolError(
            new Error(
              `Unknown pack_ids: ${invalid.join(", ")}. Valid ids: ${PACK_IDS.join(", ")}.`,
            ),
            "Call secure_mcp_analyze_architecture for recommended_packs / pack_batches, or use only known pack ids.",
          );
        }

        const packIds = uniquePackIds(params.pack_ids as PackId[]);
        const packs = packIds.map((id) => getPack(id));
        const maxItems = params.max_items ?? DEFAULT_MAX_ITEMS;
        const filtered = filterPackItems(packs, {
          categories: params.categories,
          maxItems,
        });

        const detail = params.detail ?? "summary";
        const items =
          detail === "full"
            ? filtered
            : filtered.map((item) => toItemSummary(item));

        const includeIndex = params.include_index === true;
        // Compare against the eligible (category-filtered) stream so a narrow
        // category filter is not reported as max_items truncation.
        const eligible = countEligiblePackItems(packs, params.categories);
        const truncated = eligible > filtered.length;
        const items_per_pack = countItemsPerPack(filtered, packIds);

        const data = {
          ok: true as const,
          summary: `Loaded ${packIds.length} pack(s) → ${items.length} item(s) (detail=${detail}).`,
          applied_pack_ids: packIds,
          detail,
          max_items: maxItems,
          item_count: items.length,
          truncated_by_max_items: truncated,
          items_per_pack,
          items,
          ...(includeIndex
            ? {
                available_packs: listPackSummaries().map((p) => ({
                  id: p.id,
                  title: p.title,
                  stackTags: p.stackTags,
                  itemCount: p.itemCount,
                  estimatedTokens: p.estimatedTokens,
                })),
              }
            : {}),
          notes: [
            "Do not request all packs — load only recommended_packs / pack_batches for the detected stacks.",
            "Items are fair-sampled (round-robin) across pack_ids so stack packs are not starved under max_items.",
            truncated
              ? `truncated_by_max_items: raise max_items (up to ${ABSOLUTE_MAX_ITEMS}), filter categories, or load packs individually for full text.`
              : "Prefer detail=summary unless you need full remediation/verification text.",
            "Defensive checklists only; confirm findings in real source files before reporting.",
          ],
        };

        const md = [
          `# Knowledge packs`,
          "",
          `**Applied:** ${packIds.join(", ")}`,
          `**Detail:** ${detail}`,
          `**Items:** ${items.length}`,
          "",
          ...items.map((item) => {
            const title = "title" in item ? item.title : "";
            const id = "id" in item ? item.id : "";
            const sev =
              "severityHint" in item ? String(item.severityHint) : "";
            return `- \`${id}\` (${sev}) ${title}`;
          }),
          "",
          `_Do not load unused stack packs. Confirm issues in source before remediation reports._`,
        ].join("\n");

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(
          error,
          "Pass known pack_ids from recommended_packs or pack_batches (architecture).",
        );
      }
    },
  );
}
