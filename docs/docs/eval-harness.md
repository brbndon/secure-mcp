---
title: Eval harness
description: Offline fixture recall and precision checks that keep stack isolation and planted-weakness detectors honest.
sidebar:
  label: Eval harness
  order: 10
---

`scripts/eval-audit.test.ts` is an offline smoke harness. It drives the real
secure-mcp server in memory against the committed fixtures and checks two
properties that keep the product honest:

- **Recall floor** — a planted weakness in a fixture must surface as a candidate
  finding in the expected detector family and category.
- **Precision smoke** — a known-clean or differently-stacked fixture must not
  spam cross-stack detector families, recommend the wrong knowledge packs, or
  cite clean files as findings.

## Run it

```bash
pnpm exec tsx --test scripts/eval-audit.test.ts
```

The full `pnpm test` suite includes this harness. No network and no spawned
process are required; it uses an in-memory MCP transport with
`SECURE_MCP_ALLOWED_ROOTS` scoped to `fixtures/`.

## The label contract

Expectations live in `scripts/eval-fixtures.ts` (not in fixture source). Each
fixture declares:

| Field | Meaning |
| --- | --- |
| `stacks_include` | Detected stack labels that must be present |
| `required_rule_families` | Detector families that must appear (recall floor) |
| `required_categories` | Finding categories that must appear (recall floor) |
| `forbidden_rule_families` | Detector families that must not appear |
| `forbidden_packs` | Recommended pack ids that must not appear |
| `clean_files` | Fixture-relative paths that must not be cited |
| `required_authz_gap_paths` | Architecture `authz_id` coverage-gap paths that must appear |
| `forbidden_raw_secrets` | Planted credential strings that must never appear in any tool payload |
| `expect_zero_findings` | The fixture must produce no candidates at all |

## Interpreting failures

- A **recall** failure (`missing required rule_family ...`) means a known
  weakness stopped surfacing as a candidate. This is a detector regression and
  must be investigated, not silenced by lowering the floor.
- A **precision** failure (`unexpected forbidden rule_family/pack`, or a clean
  file cited) means stack isolation regressed or a false positive appeared.
- `tiny-app` is a mixed fixture on purpose (it contains `ios/Secrets.swift`), so
  Swift families may legitimately appear. Its forbidden set only excludes the
  Expo detector families and the `expo-rn` pack.

These are smoke numbers, not a benchmark badge. Do not put recall or precision
figures into README marketing until the harness runs on real repositories and
the numbers are reproducible across stacks.
