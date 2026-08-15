import assert from "node:assert/strict";
import { spawn, spawnSync, type SpawnSyncReturns } from "node:child_process";
import { once } from "node:events";
import {
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  realpathSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { createInterface } from "node:readline";
import os from "node:os";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { MODERN_PROTOCOL_VERSION, PROJECT_VERSION } from "./test-constants.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const serverEntry = path.join(root, "dist", "index.js");
const isWindows = process.platform === "win32";

function pwshAvailable(): boolean {
  const result = spawnSync("pwsh", ["-NoProfile", "-Command", "$true"], { encoding: "utf8" });
  return result.status === 0;
}

const hasPwsh = pwshAvailable();

function ensureBuilt(): void {
  if (existsSync(serverEntry)) return;
  const result = spawnSync("pnpm", ["build"], { cwd: root, stdio: "inherit" });
  assert.equal(result.status, 0, "pnpm build failed before installer integration tests");
}

function installerCommand(action: string, shell: "bash" | "pwsh"): { command: string; args: string[] } {
  if (shell === "pwsh") {
    return {
      command: "pwsh",
      args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/install-agents.ps1", "-Action", action],
    };
  }
  return { command: "bash", args: ["scripts/install-agents.sh", action] };
}

function runInstaller(
  home: string,
  roots: string,
  action: string,
  shell: "bash" | "pwsh" = isWindows ? "pwsh" : "bash",
): SpawnSyncReturns<string> {
  const { command, args } = installerCommand(action, shell);
  return spawnSync(command, args, {
    cwd: root,
    env: {
      ...process.env,
      SECURE_MCP_INSTALL_HOME: home,
      SECURE_MCP_ALLOWED_ROOTS: roots,
    },
    encoding: "utf8",
    maxBuffer: 20 * 1024 * 1024,
  });
}

function readJson(file: string): Record<string, unknown> {
  return JSON.parse(readFileSync(file, "utf8")) as Record<string, unknown>;
}

function jsonServers(file: string): Record<string, unknown> {
  return (readJson(file).mcpServers as Record<string, unknown>) ?? {};
}

function linkTarget(file: string): string {
  if (!existsSync(file)) return "";
  try {
    return realpathSync(file);
  } catch {
    return "";
  }
}

function expectInstalled(home: string, roots: string): void {
  const pi = path.join(home, ".pi", "agent", "mcp.json");
  const cursor = path.join(home, ".cursor", "mcp.json");
  const codexConfig = path.join(home, ".codex", "config.toml");
  const codexAgent = path.join(home, ".codex", "agents", "secure-mcp.toml");

  for (const file of [pi, cursor]) {
    const entry = jsonServers(file)["secure-mcp"] as {
      command: string;
      args: string[];
      env: { SECURE_MCP_ALLOWED_ROOTS: string };
    };
    assert.equal(entry.command, "node");
    assert.deepEqual(entry.args, [serverEntry]);
    assert.equal(entry.env.SECURE_MCP_ALLOWED_ROOTS, roots);
  }
  const marker = readJson(pi).secureMcpInstall as { owner: string; version: string };
  assert.equal(marker.owner, "https://github.com/brbndon/secure-mcp");
  assert.equal(marker.version, PROJECT_VERSION);

  for (const skill of [path.join(home, ".agents", "skills", "secure-mcp"), path.join(home, ".cursor", "skills", "secure-mcp")]) {
    assert.equal(linkTarget(skill), realpathSync(path.join(root, ".agents", "skills", "secure-mcp")));
  }

  const codexText = readFileSync(codexConfig, "utf8");
  assert.match(codexText, /# secure-mcp install owner: https:\/\/github\.com\/brbndon\/secure-mcp/);
  assert.match(codexText, /\[mcp_servers\.secure-mcp\]/);
  const tomlServerEntry = serverEntry.replace(/\\/g, "\\\\");
  assert.match(codexText, new RegExp(`args = \\["${escapeRegex(tomlServerEntry)}"\\]`));
  assert.ok(existsSync(codexAgent));
  assert.equal(
    readFileSync(codexAgent, "utf8"),
    readFileSync(path.join(root, "agents", "codex.toml"), "utf8"),
  );
}

function escapeRegex(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function assertUninstalled(home: string): void {
  for (const file of [
    path.join(home, ".pi", "agent", "mcp.json"),
    path.join(home, ".cursor", "mcp.json"),
  ]) {
    if (existsSync(file)) {
      const servers = jsonServers(file);
      assert.equal("secure-mcp" in servers, false, `${file} still contains secure-mcp`);
      const data = readJson(file);
      assert.equal("secureMcpInstall" in data, false, `${file} still contains the ownership marker`);
    }
  }
  for (const skill of [path.join(home, ".agents", "skills", "secure-mcp"), path.join(home, ".cursor", "skills", "secure-mcp")]) {
    assert.equal(existsSync(skill), false, `skill not removed: ${skill}`);
  }
  const codexConfig = path.join(home, ".codex", "config.toml");
  if (existsSync(codexConfig)) {
    const text = readFileSync(codexConfig, "utf8");
    assert.equal(text.includes("[mcp_servers.secure-mcp]"), false, "codex section not removed");
  }
  assert.equal(existsSync(path.join(home, ".codex", "agents", "secure-mcp.toml")), false);
}

async function strictV2Probe(allowlist: string): Promise<void> {
  const child = spawn(process.execPath, [serverEntry], {
    cwd: root,
    env: { ...process.env, SECURE_MCP_ALLOWED_ROOTS: allowlist },
    stdio: ["pipe", "pipe", "pipe"],
  });
  const stderr: string[] = [];
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk: string) => stderr.push(chunk));
  const lines = createInterface({ input: child.stdout });
  const output = lines[Symbol.asyncIterator]();

  async function request(message: Record<string, unknown>): Promise<Record<string, unknown>> {
    child.stdin.write(`${JSON.stringify(message)}\n`);
    const next = await output.next();
    assert.equal(next.done, false, `Server stdout closed early. stderr: ${stderr.join("")}`);
    return JSON.parse(next.value as string) as Record<string, unknown>;
  }

  try {
    await once(child, "spawn");
    const discover = await request({
      jsonrpc: "2.0",
      id: 1,
      method: "server/discover",
      params: {
        _meta: {
          "io.modelcontextprotocol/protocolVersion": MODERN_PROTOCOL_VERSION,
          "io.modelcontextprotocol/clientInfo": { name: "installer-integration", version: PROJECT_VERSION },
          "io.modelcontextprotocol/clientCapabilities": {},
        },
      },
    });
    assert.ok(
      (discover.result as { supportedVersions?: string[] })?.supportedVersions?.includes(MODERN_PROTOCOL_VERSION),
      JSON.stringify(discover),
    );

    const rejected = await request({
      jsonrpc: "2.0",
      id: 2,
      method: "initialize",
      params: {
        protocolVersion: "2025-06-18",
        capabilities: {},
        clientInfo: { name: "installer-integration-legacy", version: PROJECT_VERSION },
      },
    });
    assert.equal(
      (rejected.error as { code?: number } | undefined)?.code,
      -32022,
      `legacy initialize should be rejected: ${JSON.stringify(rejected)}`,
    );
  } finally {
    lines.close();
    if (child.exitCode === null) {
      const exited = once(child, "exit");
      child.stdin.end();
      const timer = setTimeout(() => child.kill("SIGTERM"), 2_000);
      timer.unref();
      await exited;
      clearTimeout(timer);
    }
  }
}

function tempHome(label: string): string {
  return mkdtempSync(path.join(os.tmpdir(), `secure-mcp-${label}-`));
}

test("installer is idempotent, ownership-safe, and leaves temp homes clean", { timeout: 180_000 }, async () => {
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const home = tempHome("install");
    const roots = tempHome("roots");
    tempDirs.push(home, roots);
    mkdirSync(path.join(home, ".pi", "agent"), { recursive: true });
    writeFileSync(
      path.join(home, ".pi", "agent", "mcp.json"),
      JSON.stringify(
        {
          mcpServers: { other: { command: "echo", args: ["hello"] } },
          keep: { note: "unrelated" },
        },
        null,
        2,
      ),
    );

    let result = runInstaller(home, roots, "install");
    assert.equal(result.status, 0, result.stderr);
    expectInstalled(home, roots);

    const unrelated = jsonServers(path.join(home, ".pi", "agent", "mcp.json"))["other"] as Record<string, unknown>;
    assert.deepEqual(unrelated, { command: "echo", args: ["hello"] });
    assert.equal((readJson(path.join(home, ".pi", "agent", "mcp.json")).keep as { note: string }).note, "unrelated");

    result = runInstaller(home, roots, "install");
    assert.equal(result.status, 0, result.stderr);
    const codexText = readFileSync(path.join(home, ".codex", "config.toml"), "utf8");
    assert.equal((codexText.match(/\[mcp_servers\.secure-mcp\]/g) ?? []).length, 1);
    expectInstalled(home, roots);

    result = runInstaller(home, roots, "check");
    assert.equal(result.status, 0, result.stderr);

    result = runInstaller(home, roots, "uninstall");
    assert.equal(result.status, 0, result.stderr);
    assertUninstalled(home);
    const piAfter = readJson(path.join(home, ".pi", "agent", "mcp.json"));
    assert.deepEqual((piAfter.mcpServers as Record<string, unknown>)["other"], { command: "echo", args: ["hello"] });
    assert.equal((piAfter.keep as { note: string }).note, "unrelated");

    result = runInstaller(home, roots, "uninstall");
    assert.equal(result.status, 0, result.stderr);
    assertUninstalled(home);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("installer refuses conflicting non-owned entries and skills", { timeout: 120_000 }, () => {
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const jsonHome = tempHome("conflict-json");
    const roots = tempHome("roots-json");
    tempDirs.push(jsonHome, roots);
    const cursorJson = path.join(jsonHome, ".cursor", "mcp.json");
    mkdirSync(path.dirname(cursorJson), { recursive: true });
    const conflicting = { mcpServers: { "secure-mcp": { command: "python", args: ["other.py"] } } };
    writeFileSync(cursorJson, JSON.stringify(conflicting, null, 2));

    let result = runInstaller(jsonHome, roots, "install");
    assert.notEqual(result.status, 0, "install should refuse a conflicting JSON entry");
    assert.deepEqual(readJson(cursorJson), conflicting);

    const skillHome = tempHome("conflict-skill");
    const skillRoots = tempHome("roots-skill");
    tempDirs.push(skillHome, skillRoots);
    mkdirSync(path.join(skillHome, ".agents", "skills", "secure-mcp"), { recursive: true });
    result = runInstaller(skillHome, skillRoots, "install");
    assert.notEqual(result.status, 0, "install should refuse a conflicting skill path");
    assert.equal(existsSync(path.join(skillHome, ".agents", "skills", "secure-mcp")), true);

    const codexHome = tempHome("conflict-codex");
    const codexRoots = tempHome("roots-codex");
    tempDirs.push(codexHome, codexRoots);
    const codexConfig = path.join(codexHome, ".codex", "config.toml");
    mkdirSync(path.dirname(codexConfig), { recursive: true });
    const conflictingCodex = '[mcp_servers.secure-mcp]\ncommand = "python"\nargs = ["other.py"]\n';
    writeFileSync(codexConfig, conflictingCodex);
    result = runInstaller(codexHome, codexRoots, "install");
    assert.notEqual(result.status, 0, "install should refuse a conflicting Codex section");
    assert.equal(readFileSync(codexConfig, "utf8"), conflictingCodex);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("installed server starts and negotiates strict MCP v2", { timeout: 60_000 }, async () => {
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const home = tempHome("probe");
    const roots = tempHome("roots-probe");
    tempDirs.push(home, roots);
    const result = runInstaller(home, roots, "install");
    assert.equal(result.status, 0, result.stderr);
    await strictV2Probe(roots);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("setup.sh bootstraps a fresh home end-to-end", { timeout: 300_000, skip: isWindows }, () => {
  // setup.sh is Unix-only by contract; Windows uses setup.ps1 (next test).
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const home = tempHome("setup");
    const roots = tempHome("roots-setup");
    tempDirs.push(home, roots);
    const result = spawnSync("bash", ["scripts/setup.sh"], {
      cwd: root,
      env: {
        ...process.env,
        SECURE_MCP_INSTALL_HOME: home,
        SECURE_MCP_ALLOWED_ROOTS: roots,
      },
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
    });
    assert.equal(result.status, 0, result.stderr);
    expectInstalled(home, roots);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("setup.ps1 bootstraps a fresh home end-to-end", { timeout: 300_000, skip: !hasPwsh }, () => {
  if (!hasPwsh) return;
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const home = tempHome("setup-pwsh");
    const roots = tempHome("roots-setup-pwsh");
    tempDirs.push(home, roots);
    const result = spawnSync("pwsh", ["-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "scripts/setup.ps1"], {
      cwd: root,
      env: {
        ...process.env,
        SECURE_MCP_INSTALL_HOME: home,
        SECURE_MCP_ALLOWED_ROOTS: roots,
      },
      encoding: "utf8",
      maxBuffer: 20 * 1024 * 1024,
    });
    assert.equal(result.status, 0, result.stderr);
    expectInstalled(home, roots);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});

test("PowerShell installer parity", { timeout: 120_000, skip: isWindows ? false : !hasPwsh }, async () => {
  if (!hasPwsh) return;
  ensureBuilt();
  const tempDirs: string[] = [];
  try {
    const home = tempHome("pwsh");
    const roots = tempHome("roots-pwsh");
    tempDirs.push(home, roots);
    // Seed a pre-existing client config with a single-element array and an
    // explicit null field: ConvertTo-Hashtable must survive both (null values
    // used to crash the Mandatory InputObject binding and abort every action).
    const seededPi = path.join(home, ".pi", "agent", "mcp.json");
    mkdirSync(path.dirname(seededPi), { recursive: true });
    const seed = {
      mcpServers: { other: { command: "echo", args: ["hello"] } },
      keep: { note: "unrelated" },
      nullable: null,
    };
    writeFileSync(seededPi, JSON.stringify(seed, null, 2));

    let result = runInstaller(home, roots, "install", "pwsh");
    assert.equal(result.status, 0, result.stderr);
    expectInstalled(home, roots);
    result = runInstaller(home, roots, "check", "pwsh");
    assert.equal(result.status, 0, result.stderr);
    result = runInstaller(home, roots, "uninstall", "pwsh");
    assert.equal(result.status, 0, result.stderr);
    assertUninstalled(home);
    const piAfter = readJson(seededPi);
    assert.deepEqual((piAfter.mcpServers as Record<string, unknown>)["other"], {
      command: "echo",
      args: ["hello"],
    });
    assert.equal((piAfter.keep as { note: string }).note, "unrelated");
    assert.equal("nullable" in piAfter, true, "explicit null key must survive the round-trip");
    assert.equal(piAfter.nullable, null);
  } finally {
    for (const dir of tempDirs) rmSync(dir, { recursive: true, force: true });
  }
});
