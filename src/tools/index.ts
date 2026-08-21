/**
 * Register all secure-mcp tools on the given McpServer instance.
 *
 * Tool names are a stable public API for defensive secure-code-review; the
 * enforced enumeration lives in `REQUIRED_TOOLS` (scripts/test-constants.ts),
 * checked against live registrations by scripts/modern-protocol.test.ts.
 */

import type { McpServer } from "@modelcontextprotocol/server";
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
import { registerListAuthorizedRoots } from "./listAuthorizedRoots.js";
import { registerListProjects } from "./listProjects.js";
import { registerRunLocalScanners } from "./runLocalScanners.js";

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
  registerListAuthorizedRoots(server, config);
  registerListProjects(server, config);
  registerRunLocalScanners(server, config);
}
