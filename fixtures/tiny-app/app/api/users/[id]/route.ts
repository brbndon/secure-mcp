import type { NextRequest } from "next/server";

// INTENTIONAL WEAKNESSES FOR FIXTURE / SMOKE TESTS — DO NOT COPY TO PRODUCTION
// Dynamic-route handler with no object-level authorization check: demonstrates
// an authz-sensitive surface (BOLA/IDOR) for architecture prioritization.
export async function GET(request: NextRequest, { params }: { params: { id: string } }) {
  const { id } = params;
  // No ownership/authorization check before returning the user record.
  return Response.json({ id, owned: true });
}
