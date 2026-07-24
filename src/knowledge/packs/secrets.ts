/**
 * Pack: secrets — rotation, env hygiene, client-bundle exposure patterns.
 */

import type { KnowledgePack } from "./types.js";

export const secretsPack: KnowledgePack = {
  id: "secrets",
  title: "Secrets hygiene",
  description:
    "Credential rotation, env hygiene, client-bundle exposure, and secret-manager patterns.",
  stackTags: ["common", "nextjs", "expo", "swift"],
  categories: ["secrets", "configuration", "privacy"],
  estimatedTokens: 1200,
  items: [
    {
      id: "SEC-NO-HARDCODE",
      title: "No hardcoded credentials",
      description:
        "API keys, private keys, passwords, and long-lived tokens must not appear in source or committed configs.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-798",
      tags: ["hardcoded"],
      stacks: ["common"],
      impact_if_unremediated:
        "Anyone with repository or binary access holds working production credentials.",
      remediation: "Move secrets to env or a secret manager; rotate any that were committed.",
      verification_suggestion: "Run secrets review heuristics; confirm no remaining literals.",
    },
    {
      id: "SEC-ROTATE-ON-EXPOSURE",
      title: "Rotate on exposure",
      description:
        "Any secret found in git history, logs, or client bundles should be rotated immediately—not only deleted.",
      category: "secrets",
      severityHint: "critical",
      tags: ["rotation"],
      stacks: ["common"],
      impact_if_unremediated:
        "A deleted-but-live credential stays usable by anyone who already copied it.",
      remediation: "Revoke/rotate in the provider console; deploy new secret; scrub history if needed.",
      verification_suggestion: "Confirm old credential is revoked and new one is loaded from secure store.",
    },
    {
      id: "SEC-ENV-SPLIT",
      title: "Separate public vs private env",
      description:
        "Public/client env prefixes (NEXT_PUBLIC_, EXPO_PUBLIC_, VITE_, REACT_APP_) must never hold secrets.",
      category: "secrets",
      severityHint: "critical",
      cwe: "CWE-200",
      tags: ["env", "client-bundle"],
      stacks: ["common", "nextjs", "expo"],
      impact_if_unremediated:
        "Public-prefixed secrets ship to every client and must be treated as disclosed.",
      remediation: "Use server-only names for secrets; audit all public-prefixed variables.",
      verification_suggestion: "List public env vars; ensure none are secret-bearing.",
    },
    {
      id: "SEC-DOTENV-GITIGNORE",
      title: ".env files not committed",
      description:
        ".env, .env.local, and production secret files should be gitignored. Commit .env.example without values.",
      category: "secrets",
      severityHint: "high",
      tags: ["dotenv", "gitignore"],
      stacks: ["common"],
      impact_if_unremediated:
        "Committed env files spread live credentials to every clone and fork of the repository.",
      remediation: "Add secret env files to .gitignore; remove from history if committed; keep examples empty.",
      verification_suggestion: "Confirm .gitignore covers .env*; ensure no .env in the tree.",
    },
    {
      id: "SEC-SCOPE-LEAST",
      title: "Least-privilege API keys",
      description:
        "Issue scoped, environment-specific keys. Prefer short-lived credentials and workload identity over long-lived static keys.",
      category: "secrets",
      severityHint: "high",
      tags: ["least-privilege"],
      stacks: ["common"],
      impact_if_unremediated:
        "One leaked broad key exposes far more data and environments than the feature needed.",
      remediation: "Replace broad keys with scoped roles; prefer OIDC/workload identity where available.",
      verification_suggestion: "Review cloud IAM policies for each key used by the app.",
    },
    {
      id: "SEC-LOG-REDACTION",
      title: "Never log secret values",
      description:
        "Request headers, Authorization tokens, and cookie values must be redacted before logging or crash reporting.",
      category: "privacy",
      severityHint: "high",
      cwe: "CWE-532",
      tags: ["logging"],
      stacks: ["common"],
      impact_if_unremediated:
        "Log and crash-reporting stores become a long-lived copy of live credentials.",
      remediation: "Add redaction middleware; forbid logging raw headers in debug builds that ship.",
      verification_suggestion: "Sample logs and error breadcrumbs for Authorization and cookie fields.",
    },
    {
      id: "SEC-CLIENT-BUNDLE",
      title: "Audit client bundles for secrets",
      description:
        "Anything imported into client/mobile JS can appear in bundles. Keep secret modules server-only or native-secure.",
      category: "secrets",
      severityHint: "high",
      tags: ["client-bundle"],
      stacks: ["nextjs", "expo", "typescript"],
      impact_if_unremediated:
        "Secrets pulled into a client import graph are extractable from shipped bundles.",
      remediation: "Move secret access behind server APIs or SecureStore/Keychain; audit import graphs.",
      verification_suggestion: "Search client entrypoints for process.env and secret module imports.",
    },
    {
      id: "SEC-CI-SECRETS",
      title: "CI secret hygiene",
      description:
        "CI secrets should be masked, scoped to environments, and not echoed in workflow logs.",
      category: "secrets",
      severityHint: "high",
      tags: ["ci"],
      stacks: ["common"],
      impact_if_unremediated:
        "Build logs or over-privileged workflows can hand production secrets to fork contributors.",
      remediation: "Use platform secret stores; avoid printing env in scripts; limit workflow permissions.",
      verification_suggestion: "Review CI workflows for echo/print of secret env and broad permissions.",
    },
    {
      id: "SEC-EXAMPLE-PLACEHOLDERS",
      title: "Examples use placeholders only",
      description:
        "Docs, fixtures, and README samples must use obviously fake placeholders—not live or recently rotated keys.",
      category: "secrets",
      severityHint: "medium",
      tags: ["docs"],
      stacks: ["common"],
      impact_if_unremediated:
        "Real-looking samples get copied into deployments and hide genuine leaks during review.",
      remediation: "Replace real-looking samples with clearly fake values (e.g. sk_test_xxxplaceholder).",
      verification_suggestion: "Scan docs/examples for key-shaped strings that look live.",
    },
    {
      id: "SEC-MANAGER-RUNTIME",
      title: "Load secrets at runtime",
      description:
        "Prefer runtime injection from a secret manager or platform env over baking secrets into images or binaries.",
      category: "configuration",
      severityHint: "medium",
      tags: ["secret-manager"],
      stacks: ["common"],
      impact_if_unremediated:
        "Secrets baked into artifacts persist in registries and cannot be rotated without a rebuild.",
      remediation: "Inject secrets at deploy/runtime; avoid COPY of .env into container images.",
      verification_suggestion: "Inspect Dockerfiles and build scripts for secret bake-in.",
    },
  ],
};
