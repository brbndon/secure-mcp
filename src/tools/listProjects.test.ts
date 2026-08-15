/**
 * Tests for allowlist discovery:
 * secure_mcp_list_authorized_roots and secure_mcp_list_projects.
 */

import assert from "node:assert/strict";
import { promises as fs } from "node:fs";
import os from "node:os";
import path from "node:path";
import { describe, it } from "node:test";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { createServer } from "../server.js";

function makeServer(allowedRoots?: string[], overrides: object = {}) {
  const server = createServer({
    name: "secure-mcp-test",
    version: "test",
    defaultMaxFiles: 200,
    maxFileBytes: 8192,
    maxDepth: 12,
    allowedRoots,
    ...overrides,
  });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  const client = new Client({ name: "secure-mcp-test-client", version: "test" });
  return { server, client, clientTransport, serverTransport };
}

describe("secure_mcp_list_authorized_roots", () => {
  it("reports configured roots and whether each exists", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-roots-"));
    const missing = path.join(os.tmpdir(), "secure-mcp-does-not-exist-xyz");
    const { server, client, clientTransport, serverTransport } = makeServer([root, missing]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_authorized_roots",
        arguments: { response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        configured: boolean;
        root_count: number;
        roots: Array<{ path: string; exists: boolean }>;
      };
      assert.equal(data.configured, true);
      assert.equal(data.root_count, 2);
      const existing = data.roots.find((r) => r.exists);
      assert.ok(existing);
      const gone = data.roots.find((r) => !r.exists);
      assert.ok(gone);
      assert.ok(gone.path.includes("does-not-exist-xyz"));
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });

  it("returns empty when no allowlist is configured (fail-closed)", async () => {
    const { server, client, clientTransport, serverTransport } = makeServer(undefined);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_authorized_roots",
        arguments: { response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        configured: boolean;
        roots: unknown[];
      };
      assert.equal(data.configured, false);
      assert.deepEqual(data.roots, []);
    } finally {
      await client.close();
      await server.close();
    }
  });

  it("reads package.json name only when include_metadata=true", async () => {
    const root = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-roots-meta-"));
    await fs.writeFile(
      path.join(root, "package.json"),
      JSON.stringify({ name: "my-pkg" }),
      "utf8",
    );
    const { server, client, clientTransport, serverTransport } = makeServer([root]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const withMeta = await client.callTool({
        name: "secure_mcp_list_authorized_roots",
        arguments: { include_metadata: true, response_format: "json" },
      });
      const meta = withMeta.structuredContent as {
        roots: Array<{ package_name?: string; name?: string }>;
      };
      assert.equal(meta.roots[0].package_name, "my-pkg");
      assert.ok(meta.roots[0].name);

      const withoutMeta = await client.callTool({
        name: "secure_mcp_list_authorized_roots",
        arguments: { response_format: "json" },
      });
      const lean = withoutMeta.structuredContent as {
        roots: Array<{ package_name?: string }>;
      };
      assert.equal(lean.roots[0].package_name, undefined);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(root, { recursive: true, force: true });
    }
  });
});

describe("secure_mcp_list_projects", () => {
  it("discovers nested package manifests under an allowlisted parent", async () => {
    const parent = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-projects-"));
    await fs.mkdir(path.join(parent, "apps", "web"), { recursive: true });
    await fs.mkdir(path.join(parent, "apps", "api"), { recursive: true });
    await fs.mkdir(path.join(parent, "services", "billing"), { recursive: true });
    await fs.writeFile(
      path.join(parent, "apps", "web", "package.json"),
      JSON.stringify({ name: "web" }),
      "utf8",
    );
    await fs.writeFile(
      path.join(parent, "apps", "api", "package.json"),
      JSON.stringify({ name: "api" }),
      "utf8",
    );
    await fs.writeFile(path.join(parent, "services", "billing", "pyproject.toml"), "[tool]\n", "utf8");

    const { server, client, clientTransport, serverTransport } = makeServer([parent]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_projects",
        arguments: { parent_root: parent, max_depth: 4, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        parent_root: string;
        project_count: number;
        truncated: boolean;
        projects: Array<{ path: string; project_root: string; markers: string[] }>;
      };
      const paths = data.projects.map((p) => p.path);
      assert.ok(paths.includes("apps/web"));
      assert.ok(paths.includes("apps/api"));
      assert.ok(paths.includes("services/billing"));
      const billing = data.projects.find((p) => p.path === "services/billing");
      assert.ok(billing);
      assert.deepEqual(billing.markers, ["pyproject.toml"]);
      assert.equal(billing.project_root, path.join(data.parent_root, "services", "billing"));
      assert.ok(path.isAbsolute(billing.project_root));
      assert.equal(data.truncated, false);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(parent, { recursive: true, force: true });
    }
  });

  it("fails closed when parent_root is outside the allowlist", async () => {
    const allowed = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-allowed-"));
    const outside = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-outside-"));
    const { server, client, clientTransport, serverTransport } = makeServer([allowed]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_projects",
        arguments: { parent_root: outside, response_format: "json" },
      });
      assert.equal(result.isError, true);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(allowed, { recursive: true, force: true });
      await fs.rm(outside, { recursive: true, force: true });
    }
  });

  it("treats Xcode project and workspace bundles as the parent project root", async () => {
    const parent = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-projects-xcode-"));
    const iosApp = path.join(parent, "ios-app");
    const macApp = path.join(parent, "mac-app");
    const spm = path.join(parent, "spm");
    await fs.mkdir(path.join(iosApp, "App.xcodeproj"), { recursive: true });
    await fs.writeFile(path.join(iosApp, "App.xcodeproj", "project.pbxproj"), "// pbx\n", "utf8");
    await fs.mkdir(path.join(macApp, "App.xcworkspace"), { recursive: true });
    await fs.writeFile(
      path.join(macApp, "App.xcworkspace", "contents.xcworkspacedata"),
      "<?xml version=\"1.0\"?>\n",
      "utf8",
    );
    await fs.mkdir(spm, { recursive: true });
    await fs.writeFile(path.join(spm, "Package.swift"), "// swift-tools-version: 5.9\n", "utf8");

    const { server, client, clientTransport, serverTransport } = makeServer([parent]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_projects",
        arguments: { parent_root: parent, max_depth: 4, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        parent_root: string;
        projects: Array<{ path: string; project_root: string; markers: string[] }>;
      };
      const byPath = Object.fromEntries(data.projects.map((p) => [p.path, p]));
      assert.ok(byPath["ios-app"], "typical Xcode iOS app should be discovered");
      assert.deepEqual(byPath["ios-app"].markers, ["App.xcodeproj"]);
      assert.equal(byPath["ios-app"].project_root, path.join(data.parent_root, "ios-app"));
      assert.ok(byPath["mac-app"]);
      assert.deepEqual(byPath["mac-app"].markers, ["App.xcworkspace"]);
      assert.ok(byPath.spm);
      assert.deepEqual(byPath.spm.markers, ["Package.swift"]);
      assert.equal(
        data.projects.some((p) => p.path.endsWith(".xcodeproj") || p.path.endsWith(".xcworkspace")),
        false,
        "the Xcode bundle directory itself is not the project root",
      );
    } finally {
      await client.close();
      await server.close();
      await fs.rm(parent, { recursive: true, force: true });
    }
  });

  it("caps discovered projects at max_projects", async () => {
    const parent = await fs.mkdtemp(path.join(os.tmpdir(), "secure-mcp-projects-cap-"));
    for (let i = 0; i < 12; i += 1) {
      const dir = path.join(parent, `pkg-${i}`);
      await fs.mkdir(dir, { recursive: true });
      await fs.writeFile(path.join(dir, "package.json"), JSON.stringify({ name: `pkg-${i}` }), "utf8");
    }

    const { server, client, clientTransport, serverTransport } = makeServer([parent]);

    try {
      await server.connect(serverTransport);
      await client.connect(clientTransport);
      const result = await client.callTool({
        name: "secure_mcp_list_projects",
        arguments: { parent_root: parent, max_depth: 2, max_projects: 5, response_format: "json" },
      });
      assert.equal(result.isError, undefined);
      const data = result.structuredContent as {
        project_count: number;
        truncated: boolean;
        projects: unknown[];
      };
      assert.equal(data.project_count, 5);
      assert.equal(data.truncated, true);
    } finally {
      await client.close();
      await server.close();
      await fs.rm(parent, { recursive: true, force: true });
    }
  });
});
