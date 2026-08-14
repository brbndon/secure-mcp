/**
 * Cross-platform build-output cleanup (replaces shell `rm -rf`).
 */
import { rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targets = [path.join(root, "dist"), path.join(root, ".blume-verify")];

for (const target of targets) {
  rmSync(target, { recursive: true, force: true });
}
