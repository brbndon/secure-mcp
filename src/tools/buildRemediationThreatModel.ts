/**
 * Tool: secure_mcp_build_remediation_threat_model
 * STRIDE-oriented defensive threat model fragments for prioritising fixes.
 */

import type { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";
import { loadConfig, type ServerConfig } from "../config.js";
import { toolError, toolSuccess } from "../lib/envelope.js";
import {
  normalizeAuthorizedProjectRoot,
  profileProject,
  walkProject,
} from "../lib/filesystem.js";
import {
  redactCoverageReport,
  redactFinding,
  redactedSecretPath,
  redactedSecretPaths,
} from "../lib/redact.js";
import { renderMarkdownDocument } from "../lib/markdown.js";
import {
  buildFinding,
  createFindingIdFactory,
  ProjectRootInput,
  StackFocusSchema,
} from "../knowledge/findings-schema.js";
import {
  recommendCategoryPackIds,
  uniquePackIds,
  type PackId,
} from "../knowledge/packs/registry.js";
import type { Finding, StackFocus } from "../lib/types.js";

const InputSchema = ProjectRootInput.extend({
  focus_area: z
    .string()
    .max(200)
    .optional()
    .describe(
      "Optional feature or module to prioritise for hardening (e.g. 'checkout Server Actions', 'Keychain token storage')",
    ),
  assets: z
    .array(z.string().min(1).max(500))
    .max(30)
    .optional()
    .describe(
      "Assets the team must protect (e.g. 'session token', 'PII', 'payment data') — used to prioritise remediation",
    ),
}).strict();

type Input = z.infer<typeof InputSchema>;

interface RemediationThreat {
  id: string;
  stride: "S" | "T" | "R" | "I" | "D" | "E";
  stride_label: string;
  title: string;
  description: string;
  affected_assets: string[];
  related_components: string[];
  recommended_controls: string[];
  residual_risk: "high" | "medium" | "low";
  verification_suggestion: string;
  evidence_paths?: string[];
  proof_gap?: string[];
}

interface EvidenceBackedAsset {
  name: string;
  evidence_paths: string[];
  evidence_basis: "path_inventory" | "caller_supplied";
}

interface EvidenceBackedBoundary {
  boundary: string;
  evidence_paths: string[];
  evidence_basis: "path_inventory" | "inferred_from_stack";
}

interface ThreatModelEvidence {
  assets: EvidenceBackedAsset[];
  boundaries: EvidenceBackedBoundary[];
  assumptions: string[];
  invariants: string[];
  unresolved_questions: string[];
}

function buildThreatModelEvidence(
  stacks: string[],
  files: string[],
  surface: { api: string[]; auth: string[]; webview: boolean },
  callerAssets: string[],
  focus?: string,
): ThreatModelEvidence {
  const secretPaths = redactedSecretPaths(
    files.filter((file) =>
      /(^|\/)(?:\.env|credentials|service-account|GoogleService-Info)|\.(?:pem|key|entitlements)$/i.test(
        file,
      ),
    ),
  );
  const swiftStoragePaths = redactedSecretPaths(
    files.filter((file) => /keychain|userdefaults|securestore|storage/i.test(file)),
  );
  const authPaths = redactedSecretPaths(surface.auth);
  const apiPaths = redactedSecretPaths(surface.api);
  const evidenceAssets: EvidenceBackedAsset[] = [
    ...(authPaths.length
      ? [{ name: "sessions and credentials", evidence_paths: authPaths, evidence_basis: "path_inventory" as const }]
      : []),
    ...(apiPaths.length
      ? [{ name: "API and business data", evidence_paths: apiPaths, evidence_basis: "path_inventory" as const }]
      : []),
    ...(secretPaths.length
      ? [{ name: "secrets and signing/configuration material", evidence_paths: secretPaths, evidence_basis: "path_inventory" as const }]
      : []),
    ...(swiftStoragePaths.length
      ? [{ name: "device-local credentials", evidence_paths: swiftStoragePaths, evidence_basis: "path_inventory" as const }]
      : []),
  ];
  const assets: EvidenceBackedAsset[] = [
    ...evidenceAssets,
    ...callerAssets
      .filter((asset) => !evidenceAssets.some((existing) => existing.name === asset))
      .map((name) => ({ name, evidence_paths: [], evidence_basis: "caller_supplied" as const })),
  ];

  const boundaries: EvidenceBackedBoundary[] = [];
  if (apiPaths.length || authPaths.length) {
    boundaries.push({
      boundary: "client/browser input → server/API entrypoints",
      evidence_paths: [...new Set([...apiPaths, ...authPaths])],
      evidence_basis: "path_inventory",
    });
  }
  if (secretPaths.length) {
    boundaries.push({
      boundary: "source/configuration → runtime secret stores",
      evidence_paths: secretPaths,
      evidence_basis: "path_inventory",
    });
  }
  if (stacks.includes("swift") || swiftStoragePaths.length) {
    boundaries.push({
      boundary: "UI/deep links/WebView → privileged app logic and local storage",
      evidence_paths: [
        ...new Set([
          ...swiftStoragePaths,
          ...redactedSecretPaths(files.filter((file) => /webview|url|deep/i.test(file))),
        ]),
      ],
      evidence_basis: "inferred_from_stack",
    });
  }

  const unresolved_questions = [
    ...(surface.api.length ? [] : ["Which runtime/API entrypoints handle attacker-controlled input?"]),
    ...(surface.auth.length ? [] : ["Where are sessions, roles, ownership, and token refresh validated?"]),
    ...(secretPaths.length ? [] : ["Where are production secrets injected and rotated outside this tree?"]),
    ...(focus ? [`Which concrete files implement the requested focus area: ${focus}?`] : []),
    "Which deployment, identity-provider, database, and gateway controls are enforced outside the reviewed source tree?",
  ];

  return {
    assets,
    boundaries,
    assumptions: [
      "Evidence is limited to bounded path inventory; target code and build/runtime behavior were not executed.",
      "Caller-supplied assets are prioritization hints, not proof that the asset exists in the reviewed tree.",
      "Absence from the inventory is not evidence of absence when coverage is partial, capped, ignored, or symlink-limited.",
    ],
    invariants: [
      "All untrusted inputs are validated and authorized at every sensitive server or native boundary.",
      "Secrets never appear in source, client bundles, logs, or unprotected device storage.",
      "Threat-model output remains remediation guidance and never becomes exploit or bypass instructions.",
    ],
    unresolved_questions,
  };
}

const STRIDE_LABELS: Record<RemediationThreat["stride"], string> = {
  S: "Spoofing",
  T: "Tampering",
  R: "Repudiation",
  I: "Information Disclosure",
  D: "Denial of Service",
  E: "Elevation of Privilege",
};

/** Pick threat-specific evidence paths from inventory + related components. */
export function threatEvidencePaths(
  threat: Pick<RemediationThreat, "title" | "related_components" | "stride">,
  surface: { api: string[]; auth: string[]; secrets?: string[] },
  inventoryPaths: readonly string[] = [...surface.api, ...surface.auth, ...(surface.secrets ?? [])],
): string[] {
  const related = threat.related_components
    .filter((item) => item.includes("/") || item.includes("."))
    .flatMap((item) =>
      inventoryPaths.filter((path) => pathMatchesInventory(item, path)).map(redactedSecretPath),
    );
  if (related.length > 0) return [...new Set(related)].slice(0, 8);

  if (/session|credential|auth/i.test(threat.title)) {
    return redactedSecretPaths(surface.auth).slice(0, 8);
  }
  if (/secret|personal data|disclosure|log/i.test(threat.title)) {
    return redactedSecretPaths([
      ...(surface.secrets ?? []),
      ...surface.auth,
    ]).slice(0, 8);
  }
  if (surface.api.length > 0 && /object-level|input validation|Server Action|Route Handler|API/i.test(threat.title)) {
    return redactedSecretPaths(surface.api).slice(0, 8);
  }
  if (surface.auth.length > 0 && threat.stride === "S") {
    return redactedSecretPaths(surface.auth).slice(0, 8);
  }
  if (surface.api.length > 0) return redactedSecretPaths(surface.api).slice(0, 8);
  return redactedSecretPaths(surface.auth).slice(0, 8);
}

function pathMatchesInventory(component: string, inventoryPath: string): boolean {
  const normalizedComponent = component.replace(/^\/+|\/+$/g, "");
  const normalizedPath = inventoryPath.replace(/^\/+|\/+$/g, "");
  if (normalizedComponent.endsWith("/**")) {
    const prefix = normalizedComponent.slice(0, -3).replace(/\/+$/, "");
    return normalizedPath === prefix || normalizedPath.startsWith(`${prefix}/`);
  }
  return normalizedComponent === normalizedPath;
}

/** Pack ids claimed by the threat-model tool for the active stacks. */
export function threatModelPackIds(stacks: readonly string[]): PackId[] {
  const stackFocus = stacks.filter((s): s is StackFocus =>
    StackFocusSchema.options.includes(s as StackFocus),
  );
  const routedStacks: StackFocus[] = stackFocus.length ? stackFocus : ["common"];
  const categories = stackFocus.includes("nextjs")
    ? ["authentication", "authorization", "secrets", "injection-risk", "configuration", "privacy"]
    : ["secrets"];
  const recommended = recommendCategoryPackIds(routedStacks, categories);
  return uniquePackIds(["threat-model", "core", ...recommended]);
}

export const THREAT_MODEL_DETECTOR_FAMILIES = [
  "threat-model.stride",
  "web-next.stride",
  "swift-ios.stride",
] as const;
export type ThreatModelDetectorFamily = (typeof THREAT_MODEL_DETECTOR_FAMILIES)[number];

const PACK_ID_BY_THREAT_FAMILY: Record<ThreatModelDetectorFamily, PackId> = {
  "threat-model.stride": "threat-model",
  "web-next.stride": "web-next",
  "swift-ios.stride": "swift-ios",
};

/**
 * Families whose stack-gated STRIDE fragments were actually emitted.
 * Generic STRIDE is always applied; Next/Swift families only when those
 * stacks contributed threat content.
 */
export function threatModelFamiliesForStacks(
  stacks: readonly string[],
): ThreatModelDetectorFamily[] {
  const families: ThreatModelDetectorFamily[] = ["threat-model.stride"];
  if (stacks.includes("nextjs") || stacks.includes("typescript")) {
    families.push("web-next.stride");
  }
  if (stacks.includes("swift")) families.push("swift-ios.stride");
  return families;
}

/** Packs behind emitted threat-model families (content-true, not merely routed). */
export function appliedThreatModelPackIds(evaluatedFamilies: readonly string[]): PackId[] {
  const set = new Set(evaluatedFamilies);
  const ids: PackId[] = [];
  for (const family of THREAT_MODEL_DETECTOR_FAMILIES) {
    if (!set.has(family)) continue;
    const packId = PACK_ID_BY_THREAT_FAMILY[family];
    if (packId && !ids.includes(packId)) ids.push(packId);
  }
  return ids;
}

function buildThreats(
  stacks: string[],
  surface: { api: string[]; auth: string[]; webview: boolean },
  assets: string[],
  focus?: string,
): RemediationThreat[] {
  const threats: RemediationThreat[] = [];
  const push = (
    t: Omit<RemediationThreat, "id" | "stride_label"> & { stride: RemediationThreat["stride"] },
  ) => {
    threats.push({
      ...t,
      id: `TM-${String(threats.length + 1).padStart(3, "0")}`,
      stride_label: STRIDE_LABELS[t.stride],
    });
  };

  const assetList =
    assets.length > 0 ? assets : ["user session", "credentials", "PII", "business data"];

  push({
    stride: "S",
    title: "Weak session or credential validation",
    description:
      "If session or credential checks are incomplete, unauthorised parties may be treated as legitimate users. Identify gaps and strengthen validation for remediation.",
    affected_assets: assetList.filter((a) => /session|credential|token|user/i.test(a)).length
      ? assetList.filter((a) => /session|credential|token|user/i.test(a))
      : ["user session"],
    related_components: surface.auth.slice(0, 5),
    recommended_controls: [
      "Short-lived tokens with secure refresh handling",
      "Server-side session validation on every sensitive path",
      "MFA for high-impact actions where appropriate",
    ],
    residual_risk: "high",
    verification_suggestion:
      "Review auth helpers and add automated tests that unauthenticated requests cannot reach protected handlers.",
  });

  push({
    stride: "T",
    title: "Missing object-level authorization on client-supplied identifiers",
    description:
      "If handlers trust client-supplied IDs without ownership checks, users may access or modify other users' data. Flag for authorization hardening.",
    affected_assets: assetList,
    related_components: surface.api.slice(0, 8),
    recommended_controls: [
      "Enforce ownership/role checks server-side on every object access",
      "Derive privileged identifiers from the session when possible",
      "Add authorization regression tests per sensitive resource",
    ],
    residual_risk: "high",
    verification_suggestion:
      "Code-review each mutating API/Server Action for explicit authz; add negative tests for cross-user IDs.",
  });

  push({
    stride: "I",
    title: "Secrets or personal data exposed through code, logs, or client bundles",
    description:
      "Secrets in source, verbose logs, or public env vars can disclose sensitive data. Locate exposures and move secrets to proper stores.",
    affected_assets: assetList,
    related_components: ["client bundles", "server logs", "error responses", "env files"],
    recommended_controls: [
      "Secret scanning in CI",
      "Redacted structured logging",
      "Strict separation of public vs server-only configuration",
    ],
    residual_risk: "medium",
    verification_suggestion:
      "Re-run secrets review tools; confirm .gitignore and env policy; check client bundles for leaked keys.",
  });

  if (stacks.includes("nextjs") || stacks.includes("typescript")) {
    push({
      stride: "E",
      title: "Incomplete Next.js boundary checks (middleware-only protection)",
      description:
        "If authorization is only applied in middleware matchers, some Route Handlers or Server Actions may lack defense in depth. Re-enforce checks at each sensitive server entrypoint.",
      affected_assets: assetList,
      related_components: ["middleware.ts", "app/api/**", "Server Actions"],
      recommended_controls: [
        "Shared requireUser/requireRole helpers used in every sensitive entrypoint",
        "Automated tests for unauthenticated and unauthorized access",
        "Documented matcher coverage plus server-side re-checks",
      ],
      residual_risk: "high",
      verification_suggestion:
        "Map all server entrypoints and confirm each performs authn/authz independently of middleware.",
    });
    push({
      stride: "T",
      title: "Insufficient input validation on Server Actions / Route Handlers",
      description:
        "Unvalidated inputs into queries, HTML rendering, or redirects can create integrity and injection risks. Strengthen validation and safe sinks.",
      affected_assets: assetList,
      related_components: surface.api.slice(0, 8),
      recommended_controls: [
        "Schema validation (e.g. Zod) on all external inputs",
        "Parameterized queries / ORM bind parameters",
        "Allowlisted redirect destinations",
      ],
      residual_risk: "medium",
      verification_suggestion:
        "Add schema tests and ensure HTML/redirect helpers reject unexpected values.",
    });
  }

  if (stacks.includes("swift")) {
    push({
      stride: "I",
      title: "Sensitive data stored outside Keychain or with overly broad accessibility",
      description:
        "Tokens in UserDefaults or loosely protected Keychain items may be exposed on device. Move secrets to appropriate Keychain accessibility classes.",
      affected_assets: ["access tokens", "refresh tokens", "API keys"],
      related_components: ["UserDefaults", "Keychain", "App Group containers"],
      recommended_controls: [
        "Keychain with least-privilege accessibility",
        "Biometric-gated access for high-value secrets when needed",
        "Never log tokens",
      ],
      residual_risk: "medium",
      verification_suggestion:
        "Audit storage call sites; confirm no credentials remain in UserDefaults or plaintext files.",
    });
    if (surface.webview) {
      push({
        stride: "E",
        title: "Over-privileged WebView native bridges",
        description:
          "If web content can invoke native bridges without strict allowlisting, privileged APIs may be reachable. Restrict message handlers and never expose secrets to JS.",
        affected_assets: assetList,
        related_components: ["WKScriptMessageHandler", "WKWebView"],
        recommended_controls: [
          "Strict message allowlists",
          "No raw secret or filesystem exposure to web content",
          "Validate message intent before privileged actions",
        ],
        residual_risk: "high",
        verification_suggestion:
          "Review every bridge method; document allowed messages; add tests for rejected messages.",
      });
    }
    push({
      stride: "S",
      title: "Insufficient validation of deep links / universal links",
      description:
        "Unvalidated deep-link parameters can drive sensitive UI or actions with untrusted data. Validate and require re-authentication for privileged flows.",
      affected_assets: assetList,
      related_components: ["URL schemes", "universal links", "onOpenURL"],
      recommended_controls: [
        "Validate deep-link payloads against an allowlist",
        "Require re-auth for sensitive actions triggered by links",
      ],
      residual_risk: "medium",
      verification_suggestion:
        "Enumerate link handlers and add unit tests for malformed or unexpected URLs.",
    });
  }

  push({
    stride: "R",
    title: "Insufficient security-relevant audit logging",
    description:
      "Missing logs for auth failures, authorization denials, and admin actions reduce accountability. Add privacy-aware audit events without logging secrets.",
    affected_assets: ["audit trail"],
    related_components: surface.auth.slice(0, 3),
    recommended_controls: [
      "Log authentication and authorization outcomes without secrets",
      "Retain audit records per policy",
    ],
    residual_risk: "low",
    verification_suggestion:
      "Confirm sensitive actions emit audit events and that secrets never appear in log fixtures.",
  });

  push({
    stride: "D",
    title: "Missing rate limits or resource controls on expensive endpoints",
    description:
      "Login, search, upload, or AI endpoints without limits can harm availability. Add rate limiting, auth where appropriate, and payload size limits.",
    affected_assets: ["availability", ...assetList.slice(0, 2)],
    related_components: surface.api.slice(0, 5),
    recommended_controls: [
      "Rate limiting and abuse controls",
      "Authentication on expensive operations when feasible",
      "Payload size limits and timeouts",
    ],
    residual_risk: "medium",
    verification_suggestion:
      "Load-test or review gateway/config limits; document expected quotas.",
  });

  if (focus) {
    push({
      stride: "T",
      title: `Hardening focus: ${focus}`,
      description: `Prioritise remediation analysis for "${focus}". Map data flows, trust boundaries, missing controls, and concrete fixes for this feature.`,
      affected_assets: assetList,
      related_components: [focus],
      recommended_controls: [
        "Map entry points and trust boundaries for this feature",
        "Enumerate missing controls and assign remediation owners",
        "Add tests that lock in the hardened behaviour",
      ],
      residual_risk: "medium",
      verification_suggestion:
        "Produce a short control checklist for this focus area and verify each item in code review.",
    });
  }

  return threats;
}

const TOOL_DESCRIPTION = `Defensive tool: produce STRIDE-oriented remediation threat fragments and high-residual finding seeds to prioritise hardening.\n\nArgs: project_root, stack?, focus_area?, assets?, max_files?, focus_paths?, response_format.\nReturns: threats[], finding_seeds (also exposed as findings), applied_pack_ids (packs whose STRIDE fragments were emitted), knowledge_pack_traceability.consulted_pack_ids (routed packs).\n\nGuidance: Call secure_mcp_get_audit_guidance for the full workflow and guardrails.`;

export function registerBuildRemediationThreatModel(
  server: McpServer,
  config: ServerConfig = loadConfig(),
): void {
  server.registerTool(
    "secure_mcp_build_remediation_threat_model",
    {
      title: "Build remediation-focused threat model",
      description: TOOL_DESCRIPTION,
      inputSchema: InputSchema,
      annotations: {
        readOnlyHint: true,
        destructiveHint: false,
        idempotentHint: true,
        openWorldHint: false,
      },
    },
    async (params: Input) => {
      try {
        const root = await normalizeAuthorizedProjectRoot(params.project_root, config.allowedRoots);
        const effectiveMaxFiles = params.max_files ?? config.defaultMaxFiles;
        const profile = await profileProject(root, {
          focusPrefixes: params.focus_paths,
          maxFiles: effectiveMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
        });
        const stacks =
          params.stack && params.stack !== "auto" ? [params.stack] : profile.likelyStacks;

        const { files, coverageSession } = await walkProject(root, {
          maxFiles: params.max_files ?? config.defaultMaxFiles,
          maxDepth: config.maxDepth,
          maxFileBytes: config.maxFileBytes,
          maxTotalBytes: config.maxTotalBytes,
          allowedRoots: config.allowedRoots,
          focusPrefixes: params.focus_paths,
        });

        const api = files
          .filter((f) => /route\.(ts|js)$|\/api\/|actions?\.(ts|js)$/i.test(f.relativePath))
          .map((f) => f.relativePath)
          .slice(0, 40);
        const auth = files
          .filter((f) => /auth|session|middleware|login|keychain/i.test(f.relativePath))
          .map((f) => f.relativePath)
          .slice(0, 40);
        const secretFiles = files
          .filter((f) =>
            /(^|\/)(?:\.env|credentials|service-account|GoogleService-Info)|\.(?:pem|key|entitlements)$/i.test(
              f.relativePath,
            ),
          )
          .map((f) => f.relativePath)
          .slice(0, 40);
        const webview = files.some((f) => /webview|wkwebview|wkscript/i.test(f.relativePath));
        const evidence = buildThreatModelEvidence(
          stacks,
          files.map((file) => file.relativePath),
          { api, auth, webview },
          params.assets ?? [],
          params.focus_area,
        );

        const surfaceForEvidence = { api, auth, secrets: secretFiles };
        const threats = buildThreats(
          stacks,
          { api, auth, webview },
          params.assets ?? [],
          params.focus_area,
        ).map((threat) => ({
          ...threat,
          related_components: redactedSecretPaths(threat.related_components),
          evidence_paths: threatEvidencePaths(
            threat,
            surfaceForEvidence,
            files.map((file) => file.relativePath),
          ),
          proof_gap: evidence.unresolved_questions.slice(0, 3),
        }));

        const nextId = createFindingIdFactory("TM");
        const finding_seeds: Finding[] = threats
          .filter((t) => t.residual_risk === "high")
          .map((t) =>
            redactFinding(
              buildFinding({
                id: nextId(),
                title: `Remediation priority: ${t.title}`,
                description: t.description,
                severity: "high",
                confidence: "low",
                category: "threat-model-remediation",
                rule_family: "threat-model.stride",
                root_control: `TM-${t.stride}-${t.title.replace(/[^A-Z0-9]+/gi, "-").toUpperCase()}`,
                evidence: `STRIDE ${t.stride_label}; observed paths: ${
                  (t.evidence_paths ?? []).join(", ") || "none in bounded inventory"
                }`,
                source: "Bounded architecture/path inventory and caller-provided hardening focus.",
                control: t.recommended_controls.join("; "),
                sink: t.related_components.slice(0, 5).join(", ") || "unresolved boundary",
                counterevidence: [
                  "No target code, deployment, identity provider, or runtime configuration was executed or verified.",
                ],
                proof_gap: [
                  "Confirm the relevant source-to-boundary data flow and control enforcement in the target codebase.",
                  ...evidence.unresolved_questions.slice(0, 2),
                ],
                validation: [t.verification_suggestion],
                impact_if_unremediated: `If controls for "${t.title}" remain weak, ${t.affected_assets.join(", ") || "sensitive assets"} may be exposed or integrity may be compromised.`,
                remediation: t.recommended_controls.join("; "),
                residual_risk: `Residual risk rated ${t.residual_risk} until controls are implemented and verified.`,
                verification_suggestion: t.verification_suggestion,
                tags: ["threat-model", "remediation", t.stride_label],
              }),
            ),
          );

        const findings = finding_seeds;
        const consulted_pack_ids = threatModelPackIds(stacks);
        const detectorFamiliesRun = threatModelFamiliesForStacks(stacks);
        const applied_pack_ids = appliedThreatModelPackIds(detectorFamiliesRun);

        const data = {
          ok: true as const,
          project_root: root,
          summary: `Remediation threat-model fragments: ${threats.length} item(s) for stacks [${stacks.join(", ")}]${params.focus_area ? ` focusing on hardening "${params.focus_area}"` : ""}. Use controls to prioritise fixes — not for offensive planning.`,
          stacks,
          assets: params.assets ?? ["user session", "credentials", "PII", "business data"],
          evidence_backed_assets: evidence.assets,
          focus_area: params.focus_area ?? null,
          applied_pack_ids,
          knowledge_pack_traceability: {
            consulted_pack_ids,
            detector_families_run: [...detectorFamiliesRun].sort(),
            detector_families_not_run: [],
            consulted_via: "bundled STRIDE templates and routed pack metadata; no remote pack lookup",
          },
          findings,
          coverage: redactCoverageReport(coverageSession.finish(findings)),
          evidence,
          boundary_evidence: evidence.boundaries,
          assumptions: evidence.assumptions,
          invariants: evidence.invariants,
          unresolved_questions: evidence.unresolved_questions,
          trust_boundaries: stacks.includes("swift")
            ? [
                "UI / deep links → app logic (validate inputs)",
                "app logic → Keychain / local storage (protect secrets)",
                "app logic → backend APIs (authenticate and authorize)",
                "WebView content → native bridges (least privilege)",
              ]
            : [
                "Browser → Next.js middleware/edge (defense in depth)",
                "Browser → Server Actions / Route Handlers (validate + authorize)",
                "Server → data stores / third parties (least privilege credentials)",
                "CI/CD → production secrets (secret hygiene)",
              ],
          threats,
          finding_seeds,
          methodology:
            "STRIDE used defensively to prioritise hardening (Spoofing, Tampering, Repudiation, Information Disclosure, DoS, EoP)",
          notes: [
            "Defensive design review only — identify control gaps and remediations.",
            "Evidence-backed fields are based on bounded path inventory unless marked caller_supplied or inferred_from_stack.",
            "Do not generate exploits, PoCs, or bypass instructions from these fragments.",
            "Merge confirmed seeds with scan evidence via secure_mcp_produce_findings.",
            "applied_pack_ids are packs whose STRIDE fragments were emitted; knowledge_pack_traceability.consulted_pack_ids are the routed packs for this stack.",
            "Load the threat-model pack via secure_mcp_get_knowledge_pack when you need the checklist text.",
          ],
        };

        const md = renderMarkdownDocument({
          title: "Remediation-focused threat model",
          summary: data.summary,
          sections: [
            {
              heading: "Trust boundaries (for control placement)",
              bullets: data.trust_boundaries,
            },
            ...threats.map((threat) => ({
              heading: `${threat.id} [${threat.stride_label}] ${threat.title}`,
              paragraphs: [threat.description],
              fields: [
                {
                  label: "Evidence paths",
                  value: threat.evidence_paths?.join(", ") || "none in bounded inventory",
                },
                {
                  label: "Recommended controls",
                  value: threat.recommended_controls.join("; "),
                },
                {
                  label: "Proof gaps",
                  value: threat.proof_gap?.join("; ") || "manual confirmation required",
                },
                { label: "Residual risk", value: threat.residual_risk },
                { label: "Verify", value: threat.verification_suggestion },
              ],
            })),
          ],
        });

        return toolSuccess(data, {
          responseFormat: params.response_format,
          markdown: md,
        });
      } catch (error) {
        return toolError(error);
      }
    },
  );
}
