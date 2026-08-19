import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

const packageJson = JSON.parse(
  readFileSync(path.join(root, "package.json"), "utf8"),
) as {
  name: string;
  version: string;
  mcpName?: string;
  files?: string[];
  bin?: Record<string, string>;
  repository?: { url?: string };
};

const serverJson = JSON.parse(readFileSync(path.join(root, "server.json"), "utf8")) as {
  $schema: string;
  name: string;
  description: string;
  version: string;
  repository?: { url?: string; source?: string };
  packages: Array<{
    registryType: string;
    identifier: string;
    version: string;
    transport: { type: string };
    environmentVariables?: Array<{
      name: string;
      isRequired?: boolean;
      format?: string;
      isSecret?: boolean;
    }>;
  }>;
};

test("MCP Registry metadata matches package identity", () => {
  assert.equal(serverJson.$schema, "https://static.modelcontextprotocol.io/schemas/2025-12-11/server.schema.json");
  assert.equal(serverJson.name, "io.github.brbndon/secure-mcp");
  assert.equal(packageJson.mcpName, serverJson.name);
  assert.equal(serverJson.version, packageJson.version);
  assert.equal(serverJson.description.length > 0, true);
  assert.equal(serverJson.repository?.url, "https://github.com/brbndon/secure-mcp");
  assert.equal(serverJson.repository?.source, "github");

  assert.equal(serverJson.packages.length, 1);
  const pkg = serverJson.packages[0];
  assert.equal(pkg.registryType, "npm");
  assert.equal(pkg.identifier, packageJson.name);
  assert.equal(pkg.version, packageJson.version);
  assert.equal(pkg.transport.type, "stdio");

  const roots = pkg.environmentVariables?.find(
    (variable) => variable.name === "SECURE_MCP_ALLOWED_ROOTS",
  );
  assert.ok(roots, "server.json must declare SECURE_MCP_ALLOWED_ROOTS");
  assert.equal(roots.isRequired, true);
  assert.equal(roots.format, "string");
  assert.equal(roots.isSecret, false);
});

test("npm files list is server-only and matches the published bin", () => {
  assert.deepEqual(packageJson.files?.slice().sort(), [
    "CHANGELOG.md",
    "LICENSE",
    "NOTICE",
    "README.md",
    "dist/",
  ]);
  assert.equal(packageJson.bin?.["secure-mcp"], "dist/index.js");
  assert.ok(!(packageJson.files ?? []).some((entry) => entry.includes(".agents") || entry.includes("examples")));
});
