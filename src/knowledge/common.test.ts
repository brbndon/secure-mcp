/**
 * Regression tests for injection detector regex complexity.
 * The INJ-SQL-CONCAT pattern must use bounded spans so repository-controlled
 * text cannot cause superlinear regex work, and still flag real concatenation.
 * Run: pnpm test
 */

import assert from "node:assert/strict";
import { performance } from "node:perf_hooks";
import { describe, it } from "node:test";
import { INJECTION_PATTERNS } from "./common.js";
import { detectWithBudget, MAX_REGEX_EXECS_PER_DETECTOR } from "../lib/filesystem.js";

function sqlPattern() {
  const pattern = INJECTION_PATTERNS.find((p) => p.id === "INJ-SQL-CONCAT");
  assert.ok(pattern, "INJ-SQL-CONCAT must exist");
  return pattern.regex;
}

function matchesSql(source: string): boolean {
  const regex = sqlPattern();
  regex.lastIndex = 0;
  return regex.test(source);
}

describe("INJ-SQL-CONCAT bounded detector", () => {
  it("flags template-literal interpolation in query strings", () => {
    assert.ok(matchesSql("const sql = `SELECT * FROM users WHERE id = ${id}`"));
    assert.ok(matchesSql("const query = `SELECT ${cols} FROM t`"));
  });

  it("flags SQL keyword concatenation with +", () => {
    assert.ok(matchesSql('const sql = "SELECT * FROM users WHERE id = " + userId'));
    assert.ok(matchesSql("const sql = 'INSERT INTO t VALUES (' + value + ')'"));
    assert.ok(matchesSql("const q = query('SELECT ' + col + ' FROM t')"));
  });

  it("flags execute( with interpolation", () => {
    assert.ok(matchesSql("db.execute(`SELECT * FROM t WHERE id = ${id}`)"));
  });

  it("does not flag parameterized or plain queries", () => {
    assert.ok(!matchesSql('db.query("SELECT * FROM users WHERE id = ?", [id])'));
    assert.ok(!matchesSql('db.query("SELECT 1")'));
    assert.ok(!matchesSql('const sql = "SELECT * FROM users";'));
    assert.ok(!matchesSql("const x = `not a query ${value}`"));
    assert.ok(!matchesSql("query = 'SELECT * FROM t'"));
  });

  it("binds work on adversarial near-miss input", () => {
    const pattern = sqlPattern();
    // Thousands of near-miss prefixes with long quoted spans and no marker.
    const adversarial = ("query = '" + "A".repeat(500) + "';\n").repeat(2_000);
    const start = performance.now();
    const hits = detectWithBudget(pattern, adversarial);
    const elapsed = performance.now() - start;
    assert.ok(elapsed < 1_500, `SQL detector took ${elapsed.toFixed(0)}ms on adversarial input`);
    assert.ok(hits.length <= MAX_REGEX_EXECS_PER_DETECTOR);
  });

  it("still finds real concatenation inside adversarial input", () => {
    const pattern = sqlPattern();
    const adversarial = ("sql = '" + "A".repeat(500) + "'\n").repeat(500);
    const withHit =
      adversarial + 'const sql = "SELECT * FROM t WHERE id = " + input;\n';
    const hits = detectWithBudget(pattern, withHit);
    assert.ok(hits.length >= 1, "valid concatenation must not be suppressed");
  });

  it("caps zero-width global patterns without spinning", () => {
    const hits = detectWithBudget(/(?:)/g, "abc", 3);
    assert.equal(hits.length, 3);
  });
});
