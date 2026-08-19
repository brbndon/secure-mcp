/**
 * Run pnpm's dependency audit while allowing only the currently unfixable,
 * documentation-only image-size advisories pulled in by Blume.
 *
 * Keep this allowlist narrow. Any new advisory, dependency path, or package
 * owner must fail the release gate until it is reviewed explicitly.
 */
import { spawnSync } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const allowed = new Map([
  ["CVE-2025-71329", "GHSA-5p2g-fcmc-qvqq"],
  ["CVE-2025-71330", "GHSA-w3rx-r6r6-pgpr"],
]);

const result = spawnSync("pnpm", ["audit", "--audit-level", "low", "--json"], {
  cwd: root,
  encoding: "utf8",
});

if (result.error) {
  console.error(`dependency audit could not start: ${result.error.message}`);
  process.exit(1);
}

let report;
try {
  report = JSON.parse(result.stdout.trim());
} catch {
  console.error("dependency audit returned invalid JSON; refusing the release");
  if (result.stderr.trim()) console.error(result.stderr.trim());
  process.exit(1);
}

const advisories = Object.values(report.advisories ?? {});
const unexpected = [];
const accepted = [];

for (const advisory of advisories) {
  const cve = advisory.cves?.length === 1 ? advisory.cves[0] : undefined;
  const findings = advisory.findings ?? [];
  const paths = findings.flatMap((finding) => finding.paths ?? []);
  const isAllowed =
    advisory.module_name === "image-size" &&
    advisory.severity === "high" &&
    advisory.patched_versions === "<0.0.0" &&
    cve !== undefined &&
    allowed.has(cve) &&
    paths.length > 0 &&
    paths.every((dependencyPath) => dependencyPath === ".>blume>image-size");

  if (!isAllowed) {
    unexpected.push(advisory);
    continue;
  }

  accepted.push({
    cve,
    ghsa: allowed.get(cve),
    version: findings.map((finding) => finding.version).join(", "),
  });
}

if (unexpected.length > 0) {
  console.error("dependency audit found unapproved advisories:");
  for (const advisory of unexpected) {
    console.error(
      `- ${advisory.module_name ?? "unknown package"}: ${advisory.title ?? "unknown advisory"}`,
    );
  }
  process.exit(1);
}

if (result.status !== 0 && accepted.length === 0) {
  console.error("dependency audit failed without a reviewed exception");
  if (result.stderr.trim()) console.error(result.stderr.trim());
  process.exit(1);
}

if (accepted.length > 0) {
  console.error("accepted reviewed, unfixable documentation-toolchain advisories:");
  for (const advisory of accepted) {
    console.error(`- ${advisory.cve} (${advisory.ghsa}), image-size ${advisory.version}, via Blume only`);
  }
}

console.log(`dependency audit passed (${advisories.length} advis${advisories.length === 1 ? "ory" : "ories"} reviewed).`);
