/**
 * Deterministic release identity check used by release:check and the manual
 * post-merge release workflow. Fails unless every metadata surface names the
 * same requested version.
 *
 * Usage: node scripts/check-release-identity.mjs [2.0.0]
 */
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requested = process.argv[2] ?? "2.0.0";

const packageJson = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
const serverJson = JSON.parse(readFileSync(path.join(root, "server.json"), "utf8"));
const configSource = readFileSync(path.join(root, "src", "config.ts"), "utf8");
const changelog = readFileSync(path.join(root, "CHANGELOG.md"), "utf8");

const serverVersion = configSource.match(/export const SERVER_VERSION = "([^"]+)"/)?.[1];
const changelogSection = new RegExp(`^## ${requested.replaceAll(".", "\\.")}( — |\n)`, "m");

const failures = [];
if (packageJson.version !== requested) failures.push(`package.json version is ${packageJson.version}`);
if (packageJson.mcpName !== serverJson.name) failures.push("package.json mcpName does not match server.json name");
if (serverJson.version !== requested) failures.push(`server.json version is ${serverJson.version}`);
if (serverJson.packages?.[0]?.version !== requested) failures.push("server.json package version mismatch");
if (serverVersion !== requested) failures.push(`SERVER_VERSION is ${serverVersion}`);
if (!changelogSection.test(changelog)) failures.push(`CHANGELOG.md has no ${requested} section`);

if (failures.length > 0) {
  console.error(`release identity check failed for ${requested}:`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log(`release identity OK: package.json, server.json, SERVER_VERSION, and CHANGELOG all name ${requested}.`);
