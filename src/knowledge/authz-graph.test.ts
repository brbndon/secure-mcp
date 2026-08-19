/**
 * Unit tests for the shared authorization surface-graph classifier.
 * Run: pnpm exec tsx --test src/knowledge/authz-graph.test.ts
 */

import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  authzNodeId,
  classifyAuthzHandler,
  isAuthzSensitivePath,
  isWebObjectHandlerPath,
  shouldEmitObjectLevelAuthzCandidate,
} from "./authz-graph.js";

describe("authzNodeId", () => {
  it("is a stable path-based join key", () => {
    assert.equal(authzNodeId("app/api/users/[id]/route.ts"), "authz:app/api/users/[id]/route.ts");
    assert.equal(authzNodeId("app\\api\\users\\[id]\\route.ts"), "authz:app/api/users/[id]/route.ts");
  });
});

describe("isWebObjectHandlerPath", () => {
  it("accepts Next route handlers, pages API, and server actions", () => {
    assert.equal(isWebObjectHandlerPath("app/api/users/[id]/route.ts"), true);
    assert.equal(isWebObjectHandlerPath("pages/api/users.ts"), true);
    assert.equal(isWebObjectHandlerPath("app/actions/billing.ts"), true);
  });

  it("rejects Expo screens, Swift, and generic helpers", () => {
    assert.equal(isWebObjectHandlerPath("app/user/[id].tsx"), false);
    assert.equal(isWebObjectHandlerPath("Linking.ts"), false);
    assert.equal(isWebObjectHandlerPath("App.swift"), false);
    assert.equal(isWebObjectHandlerPath("lib/auth.ts"), false);
  });
});

describe("classifyAuthzHandler", () => {
  it("flags a dynamic-id route with no owner predicate", () => {
    const source = `
export async function GET(request: Request, { params }: { params: { id: string } }) {
  const { id } = params;
  return Response.json({ id, owned: true });
}
`;
    const classified = classifyAuthzHandler("app/api/users/[id]/route.ts", source);
    assert.equal(classified.object_or_tenant_id, true);
    assert.equal(classified.owner_predicate_observed, false);
    assert.equal(classified.id, "authz:app/api/users/[id]/route.ts");
    assert.equal(shouldEmitObjectLevelAuthzCandidate(classified.path, classified), true);
  });

  it("does not treat fixture prose like owned: true as a predicate", () => {
    const classified = classifyAuthzHandler(
      "app/api/users/[id]/route.ts",
      "return Response.json({ id, owned: true });",
    );
    assert.equal(classified.owner_predicate_observed, false);
  });

  it("observes a where-clause owner predicate", () => {
    const source = `
export async function GET(_req: Request, { params }: { params: { id: string } }) {
  const session = await auth();
  const user = await db.user.findFirst({ where: { id: params.id, userId: session.user.id } });
  return Response.json(user);
}
`;
    const classified = classifyAuthzHandler("app/api/users/[id]/route.ts", source);
    assert.equal(classified.object_or_tenant_id, true);
    assert.equal(classified.owner_predicate_observed, true);
    assert.equal(shouldEmitObjectLevelAuthzCandidate(classified.path, classified), false);
  });

  it("observes an ownerId comparison", () => {
    const source = `
if (resource.ownerId !== session.user.id) return Response.json({ error: "forbidden" }, { status: 403 });
`;
    const classified = classifyAuthzHandler("app/api/posts/[id]/route.ts", source);
    assert.equal(classified.owner_predicate_observed, true);
  });

  it("observes a named ownership helper", () => {
    const classified = classifyAuthzHandler(
      "app/api/orgs/[orgId]/route.ts",
      "await assertOwner(session, resource);\n",
    );
    assert.equal(classified.owner_predicate_observed, true);
  });

  it("does not treat null/undefined validation guards as owner predicates", () => {
    const nullGuard = classifyAuthzHandler(
      "app/api/users/[id]/route.ts",
      `export async function GET(_req: Request, { params }: { params: { userId: string } }) {
  const { userId } = params;
  if (userId == null) return Response.json({ error: "bad request" }, { status: 400 });
  const user = await db.user.findUnique({ where: { id: userId } });
  return Response.json(user);
}
`,
    );
    assert.equal(nullGuard.owner_predicate_observed, false);
    assert.equal(shouldEmitObjectLevelAuthzCandidate(nullGuard.path, nullGuard), true);

    const undefinedGuard = classifyAuthzHandler(
      "app/api/users/[id]/route.ts",
      `const userId = params.userId;
if (userId === undefined) return Response.json({}, { status: 400 });`,
    );
    assert.equal(undefinedGuard.owner_predicate_observed, false);

    const nullLhs = classifyAuthzHandler(
      "app/api/users/[id]/route.ts",
      `if (null === record.ownerId) return Response.json({}, { status: 404 });`,
    );
    assert.equal(nullLhs.owner_predicate_observed, false);
  });

  it("still observes real owner predicates after guard neutralization", () => {
    const source = `const { userId } = params;
if (userId === undefined) return Response.json({}, { status: 400 });
if (resource.ownerId !== session.user.id) return Response.json({ error: "forbidden" }, { status: 403 });`;
    const classified = classifyAuthzHandler("app/api/posts/[id]/route.ts", source);
    assert.equal(classified.owner_predicate_observed, true);
    assert.equal(shouldEmitObjectLevelAuthzCandidate(classified.path, classified), false);
  });
});

describe("isAuthzSensitivePath re-export", () => {
  it("still flags dynamic routes and not generic search", () => {
    assert.equal(isAuthzSensitivePath("app/api/users/[id]/route.ts"), true);
    assert.equal(isAuthzSensitivePath("app/api/search/route.ts"), false);
  });
});
