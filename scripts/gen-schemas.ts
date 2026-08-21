/**
 * Generate machine-readable JSON Schema artifacts from the Zod source of
 * truth in src/knowledge/findings-schema.ts.
 *
 * Run: pnpm gen:schemas
 *
 * The committed artifact under schemas/ is the published Finding contract for
 * non-TS consumers. scripts/finding-schema-artifact.test.ts regenerates it and
 * fails on drift, so the artifact can never silently diverge from the Zod
 * schema that produce_findings actually enforces.
 */

import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";
import { FindingSchema } from "../src/knowledge/findings-schema.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/**
 * Build the standalone JSON Schema for a single finding. `io: "input"` keeps
 * optional fields optional on the producer side: agents authoring findings are
 * inputs to produce_findings, not outputs of it.
 */
export function findingJsonSchema(): Record<string, unknown> {
  return z.toJSONSchema(FindingSchema, { io: "input", target: "draft-2020-12" }) as Record<
    string,
    unknown
  >;
}

/** Deterministic serialization so the drift check compares byte-for-byte. */
export function renderFindingSchemaArtifact(): string {
  return `${JSON.stringify(findingJsonSchema(), null, 2)}\n`;
}

async function main(): Promise<void> {
  const outDir = path.join(repoRoot, "schemas");
  await mkdir(outDir, { recursive: true });
  const artifact = renderFindingSchemaArtifact();
  await writeFile(path.join(outDir, "finding.schema.json"), artifact, "utf8");
  console.error(`[secure-mcp] wrote schemas/finding.schema.json (${artifact.length} bytes)`);
}

const invokedDirectly =
  process.argv[1] !== undefined && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
  main().catch((error: unknown) => {
    console.error(`[secure-mcp] Fatal: ${error instanceof Error ? error.message : String(error)}`);
    process.exit(1);
  });
}
