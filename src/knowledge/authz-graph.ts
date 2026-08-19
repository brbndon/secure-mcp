/**
 * Shared authorization surface-graph helpers.
 *
 * Architecture inventories handlers; checkAuthentication emits needs_review
 * candidates. Both sides use the same path key (`authz:<relativePath>`) so
 * coverage gaps and auth findings join without a server-side session store.
 * Regexes live in common.ts / nextjs.ts — this module only classifies.
 */

import {
  hasObjectOrTenantIdentifierCode,
  hasObjectOrTenantIdentifierPath,
  hasOwnerOrTenantPredicate,
  isAuthzSensitivePath,
} from "./common.js";
import { hasNextObjectOrTenantIdentifier } from "./nextjs.js";

export { isAuthzSensitivePath };

/** Stable join key shared by architecture gaps and auth findings. */
export function authzNodeId(relativePath: string): string {
  return `authz:${relativePath.replace(/\\/g, "/")}`;
}

export const AUTHZ_RULE_FAMILY = "core.authorization";
export const AUTHZ_ROOT_CONTROL = "CMN-AUTHZ-IDOR";

export interface AuthzHandlerClass {
  id: string;
  path: string;
  object_or_tenant_id: boolean;
  owner_predicate_observed: boolean;
}

/** Web/API handler that can take a resource identifier (not an Expo screen). */
export function isWebObjectHandlerPath(relativePath: string): boolean {
  if (!/\.[cm]?[jt]sx?$/i.test(relativePath)) return false;
  const base = relativePath.split("/").pop() ?? "";
  if (/^route\.[cm]?[jt]sx?$/i.test(base)) return true;
  if (/(?:^|\/)(?:src\/)?pages\/api\//i.test(relativePath)) return true;
  if (/(^|\/)actions?\//i.test(relativePath)) return true;
  return false;
}

/**
 * Classify one inventoried handler. Absence of a predicate is not a
 * confirmed vulnerability — callers emit a sampleable gap or needs_review.
 */
export function classifyAuthzHandler(
  relativePath: string,
  content = "",
): AuthzHandlerClass {
  const object_or_tenant_id =
    hasObjectOrTenantIdentifierPath(relativePath) ||
    hasObjectOrTenantIdentifierCode(content) ||
    hasNextObjectOrTenantIdentifier(relativePath, content);
  return {
    id: authzNodeId(relativePath),
    path: relativePath.replace(/\\/g, "/"),
    object_or_tenant_id,
    owner_predicate_observed: hasOwnerOrTenantPredicate(content),
  };
}

/** Emit an object-level IDOR candidate only for web handlers with an identifier. */
export function shouldEmitObjectLevelAuthzCandidate(
  relativePath: string,
  classification: AuthzHandlerClass,
): boolean {
  return (
    isWebObjectHandlerPath(relativePath) &&
    classification.object_or_tenant_id &&
    !classification.owner_predicate_observed
  );
}
