// INTENTIONAL WEAKNESSES FOR FIXTURE / REMEDIATION SMOKE TESTS
export const JWT_SECRET = "super-secret-hardcoded-jwt-key-12345";

export function getUser(token: string) {
  // pretend verify
  return { id: 1, token };
}

export const stripeKey = "sk_live_fixtureexamplekeynotreal000";
