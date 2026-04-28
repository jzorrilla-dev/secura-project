import path from "path";
import { scanPackageJson } from "../scanners/scripts.js";
import { scanSourceCode, scanNodeModulesFiles } from "../scanners/files.js";
import { auditEnvironment } from "../auditors/environment.js";
import { auditGitignore } from "../auditors/gitignore.js";
import { applyHardening } from "../hardening/apply.js";
import { patterns, lifecycleScriptPatterns } from "../patterns/index.js";
import { MCPMethods } from "./types.js";

function sanitizeFindings(findings) {
  return findings.map((f) => ({
    type: f.type,
    severity: f.severity,
    category: f.category,
    file: f.file,
    line: f.line,
    script: f.script,
    package: f.package,
    patternId: f.patternId,
    description: f.description,
    explanation: f.explanation,
  }));
}

export async function handleMCPRequest(method, params = {}) {
  switch (method) {
    case MCPMethods.HEALTHCHECK:
      return {
        status: "healthy",
        version: "0.1.0",
        capabilities: [
          "scan",
          "scan-with-env",
          "apply-hardening",
          "get-patterns",
        ],
      };

    case MCPMethods.GET_PATTERNS:
      return {
        patterns: patterns.map((p) => ({
          id: p.id,
          severity: p.severity,
          category: p.category,
          description: p.description,
        })),
        lifecyclePatterns: lifecycleScriptPatterns.map((p) => ({
          id: p.id,
          severity: p.severity,
          category: p.category,
          description: p.description,
        })),
      };

    case MCPMethods.SCAN: {
      const projectPath = params.path || process.cwd();
      const findings = [];

      if (params.includeScripts !== false) {
        findings.push(...scanPackageJson(projectPath));
      }

      if (params.includeSource !== false) {
        findings.push(...scanSourceCode(projectPath));
      }

      if (params.includeModules) {
        findings.push(...scanNodeModulesFiles(projectPath));
      }

      const high = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
      const medium = findings.filter((f) => f.severity === "medium").length;
      const low = findings.filter((f) => f.severity === "low").length;

      return {
        projectPath,
        totalFindings: findings.length,
        findings: sanitizeFindings(findings),
        summary: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high,
          medium,
          low,
          riskLevel: high > 0 ? "HIGH" : medium > 0 ? "MEDIUM" : "LOW",
        },
      };
    }

    case MCPMethods.SCAN_WITH_ENV: {
      const projectPath = params.path || process.cwd();
      const findings = [];

      if (params.includeScripts !== false) {
        findings.push(...scanPackageJson(projectPath));
      }

      if (params.includeSource !== false) {
        findings.push(...scanSourceCode(projectPath));
      }

      if (params.includeModules) {
        findings.push(...scanNodeModulesFiles(projectPath));
      }

      const envAudit = auditEnvironment(projectPath);
      const gitignoreAudit = auditGitignore(projectPath);

      const high = findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
      const medium = findings.filter((f) => f.severity === "medium").length;
      const low = findings.filter((f) => f.severity === "low").length;

      return {
        projectPath,
        totalFindings: findings.length,
        findings: sanitizeFindings(findings),
        summary: {
          critical: findings.filter((f) => f.severity === "critical").length,
          high,
          medium,
          low,
          riskLevel: high > 0 ? "HIGH" : medium > 0 ? "MEDIUM" : "LOW",
        },
        environment: {
          packageManager: envAudit.packageManager,
          recommendations: envAudit.recommendations.map((r) => ({
            key: r.key,
            current: r.currentValue,
            recommended: r.recommendedValue,
            severity: r.severity,
          })),
          gitignore: {
            exists: gitignoreAudit.exists,
            missing: gitignoreAudit.missing.map((m) => ({
              pattern: m.pattern,
              severity: m.severity,
            })),
          },
          hardeningNeeded:
            envAudit.recommendations.length > 0 ||
            gitignoreAudit.missing.length > 0,
        },
      };
    }

    case MCPMethods.APPLY_HARDENING: {
      const projectPath = params.path || process.cwd();
      const packageManager = params.packageManager || "npm";
      const applyOptions = {
        npmrc: params.applyNpmrc !== false,
        gitignore: params.applyGitignore !== false,
        engineStrict: params.applyEngineStrict !== false,
      };

      const results = applyHardening(projectPath, packageManager, applyOptions);

      return {
        success: results.errors.length === 0,
        projectPath,
        applied: {
          npmrc: results.npmrc ? {
            applied: results.npmrc.applied,
            updated: results.npmrc.updated,
          } : null,
          gitignore: results.gitignore ? {
            added: results.gitignore.added,
            total: results.gitignore.total,
          } : null,
          packageJson: results.packageJson || null,
        },
        errors: results.errors,
      };
    }

    default:
      throw new Error(`Unknown method: ${method}`);
  }
}