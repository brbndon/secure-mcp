export const MODERN_PROTOCOL_VERSION = "2026-07-28";
export const PROJECT_VERSION = "2.0.0";
export const LEGACY_PROTOCOL_VERSION = "2025-06-18";

export const REQUIRED_TOOLS = [
  "secure_mcp_list_project_structure",
  "secure_mcp_analyze_architecture",
  "secure_mcp_get_knowledge_pack",
  "secure_mcp_get_audit_guidance",
  "secure_mcp_check_authentication",
  "secure_mcp_analyze_injection_risks",
  "secure_mcp_review_secrets",
  "secure_mcp_build_remediation_threat_model",
  "secure_mcp_produce_findings",
] as const;
