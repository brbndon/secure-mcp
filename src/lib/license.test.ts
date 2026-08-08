import assert from "node:assert/strict";
import { generateKeyPairSync, sign } from "node:crypto";
import { describe, it } from "node:test";
import { DEV_LICENSE_KEY, validateLicenseKey } from "./license.js";

describe("license validation", () => {
  it("rejects arbitrary production-looking tokens", () => {
    const previousMode = process.env.SECURE_MCP_DEV_MODE;
    const previousPublicKey = process.env.SECURE_MCP_LICENSE_PUBLIC_KEY;
    delete process.env.SECURE_MCP_DEV_MODE;
    delete process.env.SECURE_MCP_LICENSE_PUBLIC_KEY;
    try {
      assert.equal(validateLicenseKey("smcp_arbitrary_production_token_1234").valid, false);
    } finally {
      if (previousMode === undefined) delete process.env.SECURE_MCP_DEV_MODE;
      else process.env.SECURE_MCP_DEV_MODE = previousMode;
      if (previousPublicKey === undefined) delete process.env.SECURE_MCP_LICENSE_PUBLIC_KEY;
      else process.env.SECURE_MCP_LICENSE_PUBLIC_KEY = previousPublicKey;
    }
  });

  it("accepts only a signature verified by the configured public key", () => {
    const previousMode = process.env.SECURE_MCP_DEV_MODE;
    const previousPublicKey = process.env.SECURE_MCP_LICENSE_PUBLIC_KEY;
    delete process.env.SECURE_MCP_DEV_MODE;
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    process.env.SECURE_MCP_LICENSE_PUBLIC_KEY = publicKey.export({ type: "spki", format: "pem" }).toString();
    const payload = "smcp_prod_payload_123456789";
    const signature = sign(null, Buffer.from(payload, "utf8"), privateKey).toString("base64url");
    try {
      assert.equal(validateLicenseKey(`${payload}.${signature}`).valid, true);
      assert.equal(validateLicenseKey(`${payload}.${signature.slice(0, -1)}x`).valid, false);
    } finally {
      if (previousMode === undefined) delete process.env.SECURE_MCP_DEV_MODE;
      else process.env.SECURE_MCP_DEV_MODE = previousMode;
      if (previousPublicKey === undefined) delete process.env.SECURE_MCP_LICENSE_PUBLIC_KEY;
      else process.env.SECURE_MCP_LICENSE_PUBLIC_KEY = previousPublicKey;
    }
  });

  it("keeps the documented development key gated behind dev mode", () => {
    const previousMode = process.env.SECURE_MCP_DEV_MODE;
    process.env.SECURE_MCP_DEV_MODE = "1";
    try {
      assert.equal(validateLicenseKey(DEV_LICENSE_KEY).valid, true);
    } finally {
      if (previousMode === undefined) delete process.env.SECURE_MCP_DEV_MODE;
      else process.env.SECURE_MCP_DEV_MODE = previousMode;
    }
  });
});
