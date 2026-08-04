import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  secretsPackIdsForStack,
  shouldRunNextjsSecretDetectors,
  shouldRunSwiftSecretDetectors,
} from "./reviewSecrets.js";

describe("secrets stack routing", () => {
  it("does not run or claim Next.js detectors for explicit expo or common focus", () => {
    assert.equal(shouldRunNextjsSecretDetectors("expo"), false);
    assert.equal(shouldRunNextjsSecretDetectors("common"), false);
    assert.equal(shouldRunNextjsSecretDetectors("swift"), false);
    assert.equal(shouldRunNextjsSecretDetectors("nextjs"), true);
    assert.equal(shouldRunNextjsSecretDetectors("typescript"), false);
    assert.equal(shouldRunNextjsSecretDetectors("auto"), true);

    assert.deepEqual(secretsPackIdsForStack("expo"), ["core", "secrets"]);
    assert.deepEqual(secretsPackIdsForStack("common"), ["core", "secrets"]);
    assert.ok(!secretsPackIdsForStack("expo").includes("web-next"));
    assert.ok(secretsPackIdsForStack("nextjs").includes("web-next"));
    assert.ok(!secretsPackIdsForStack("typescript").includes("web-next"));
  });

  it("runs Swift secret detectors only for auto or swift focus", () => {
    assert.equal(shouldRunSwiftSecretDetectors("swift"), true);
    assert.equal(shouldRunSwiftSecretDetectors("auto"), true);
    assert.equal(shouldRunSwiftSecretDetectors("expo"), false);
    assert.equal(shouldRunSwiftSecretDetectors("nextjs"), false);
    assert.ok(secretsPackIdsForStack("swift").includes("swift-ios"));
    assert.ok(!secretsPackIdsForStack("expo").includes("swift-ios"));
  });
});
