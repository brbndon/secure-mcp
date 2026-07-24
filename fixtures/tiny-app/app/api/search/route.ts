import { exec } from "node:child_process";

// INTENTIONAL WEAKNESSES FOR FIXTURE / SMOKE TESTS — DO NOT COPY TO PRODUCTION
export async function GET(request: Request) {
  const { searchParams } = new URL(request.url);
  const q = searchParams.get("q") ?? "";

  // Unsafe process construction (remediation: fixed argv, no shell interpolation)
  exec(`echo ${q}`, () => undefined);

  // Unsafe query construction (remediation: parameterized queries)
  const sql = "SELECT * FROM users WHERE name = '" + q + "'";

  // Unvalidated redirect target (remediation: allowlist destinations)
  const next = searchParams.get("next");
  if (next) {
    return Response.redirect(next);
  }

  return Response.json({ sql, ok: true });
}
