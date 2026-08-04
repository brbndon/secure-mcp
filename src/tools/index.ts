/**
 * Register all secure-mcp tools on the given McpServer instance.
 *
 * Tool names are a stable public API for defensive secure-code-review.
 */

import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { loadConfig, type ServerConfig } from "../config.js";
import { registerListProjectStructure } from "./listProjectStructure.js";
import { registerAnalyzeArchitecture } from "./analyzeArchitecture.js";
import { registerGetKnowledgePack } from "./getKnowledgePack.js";
import { registerCheckAuthentication } from "./checkAuthentication.js";
import { registerAnalyzeInjectionRisks } from "./analyzeInjectionRisks.js";
import { registerReviewSecrets } from "./reviewSecrets.js";
import { registerBuildRemediationThreatModel } from "./buildRemediationThreatModel.js";
import { registerProduceFindings } from "./produceFindings.js";
import { registerGetAuditGuidance } from "./getAuditGuidance.js";

/** Canonical tool names — treat as stable public API (defensive framing). */
export const TOOL_NAMES = [
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

export type ToolName = (typeof TOOL_NAMES)[number];

export function registerAllTools(server: McpServer, config: ServerConfig = loadConfig()): void {
  registerListProjectStructure(server, config);
  registerAnalyzeArchitecture(server, config);
  registerGetKnowledgePack(server);
  registerGetAuditGuidance(server);
  registerCheckAuthentication(server, config);
  registerAnalyzeInjectionRisks(server, config);
  registerReviewSecrets(server, config);
  registerBuildRemediationThreatModel(server, config);
  registerProduceFindings(server);
}
