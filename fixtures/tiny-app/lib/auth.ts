// INTENTIONAL WEAKNESSES FOR FIXTURE / REMEDIATION SMOKE TESTS
export const JWT_SECRET = "super-secret-hardcoded-jwt-key-12345";

export function getUser(token: string) {
  // pretend verify
  return { id: 1, token };
}

// Non-vendor-shaped planted credential for the secret-safe first-scan demo.
// Must not look like a live Stripe/GitHub/AWS token.
export const apiKey = "planted_secure_mcp_eval_api_key_value_123456";
