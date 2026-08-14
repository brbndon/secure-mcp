/**
 * Extract a versioned section from CHANGELOG.md for GitHub release notes.
 * Usage: node scripts/release-notes.mjs 2.0.0
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const version = process.argv[2] ?? "2.0.0";
const changelog = readFileSync(path.join(root, "CHANGELOG.md"), "utf8");
const start = changelog.search(new RegExp(`^## ${version.replaceAll(".", "\\.")}( — |\n)`, "m"));
if (start < 0) {
  console.error(`No changelog section for ${version}`);
  process.exit(1);
}
const afterStart = changelog.indexOf("\n", start) + 1;
const end = changelog.search(/^## /m);
const section = changelog.slice(afterStart, end < afterStart ? undefined : end).trimEnd();
console.log(`# secure-mcp ${version}\n\n${section}`);
