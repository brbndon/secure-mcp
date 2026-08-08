import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, it } from "node:test";
import { loadConfig, SERVER_VERSION } from "./config.js";

const originalAllowedRoots = process.env.SECURE_MCP_ALLOWED_ROOTS;
const originalDevMode = process.env.SECURE_MCP_DEV_MODE;

afterEach(() => {
  if (originalAllowedRoots === undefined) delete process.env.SECURE_MCP_ALLOWED_ROOTS;
  else process.env.SECURE_MCP_ALLOWED_ROOTS = originalAllowedRoots;

  if (originalDevMode === undefined) delete process.env.SECURE_MCP_DEV_MODE;
  else process.env.SECURE_MCP_DEV_MODE = originalDevMode;
});

describe("loadConfig filesystem allowlist", () => {
  it("fails closed when no roots are configured, including with the legacy dev flag", () => {
    delete process.env.SECURE_MCP_ALLOWED_ROOTS;
    process.env.SECURE_MCP_DEV_MODE = "1";

    assert.deepEqual(loadConfig().allowedRoots, []);
  });

  it("parses multiple configured roots with the platform delimiter", () => {
    const roots = [path.resolve("fixtures/tiny-app"), path.resolve("fixtures/tiny-swift")];
    process.env.SECURE_MCP_ALLOWED_ROOTS = roots.join(path.delimiter);

    assert.deepEqual(loadConfig().allowedRoots, roots);
  });
});

describe("release metadata", () => {
  it("keeps the server protocol version aligned with package.json", () => {
    const packageJson = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version: string };

    assert.equal(SERVER_VERSION, packageJson.version);
  });
});
