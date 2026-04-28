import { readFileSync, existsSync, readdirSync } from "fs";
import path from "path";
import { lifecycleScriptPatterns } from "../patterns/index.js";

const LIFECYCLE_SCRIPTS = [
  "preinstall",
  "install",
  "postinstall",
  "preuninstall",
  "postuninstall",
  "prepare",
  "prepublish",
];

export function scanPackageJson(projectPath) {
  const findings = [];
  const pkgPath = path.join(projectPath, "package.json");

  if (!existsSync(pkgPath)) return findings;

  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    return findings;
  }

  const scripts = pkg.scripts || {};

  for (const scriptName of LIFECYCLE_SCRIPTS) {
    if (!scripts[scriptName]) continue;

    const scriptValue = scripts[scriptName];

    for (const pattern of lifecycleScriptPatterns) {
      if (pattern.regex.test(scriptValue)) {
        findings.push({
          type: "package-json-script",
          severity: pattern.severity,
          category: pattern.category,
          file: "package.json",
          script: scriptName,
          value: scriptValue,
          patternId: pattern.id,
          description: pattern.description,
          explanation: pattern.explanation,
        });
      }
    }
  }

  return findings;
}

export function scanNodeModulesScripts(projectPath) {
  const findings = [];
  const nodeModulesPath = path.join(projectPath, "node_modules");

  if (!existsSync(nodeModulesPath)) return findings;

  let packages = [];
  try {
    const entries = readdirSync(nodeModulesPath);
    packages = entries.filter((e) => !e.startsWith("."));
  } catch {
    return findings;
  }

  for (const pkgName of packages) {
    const pkgJsonPath = path.join(nodeModulesPath, pkgName, "package.json");
    if (!existsSync(pkgJsonPath)) continue;

    let pkg;
    try {
      pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
    } catch {
      continue;
    }

    const scripts = pkg.scripts || {};

    for (const scriptName of LIFECYCLE_SCRIPTS) {
      if (!scripts[scriptName]) continue;

      const scriptValue = scripts[scriptName];

      for (const pattern of lifecycleScriptPatterns) {
        if (pattern.regex.test(scriptValue)) {
          findings.push({
            type: "node-modules-script",
            severity: pattern.severity,
            category: pattern.category,
            file: `node_modules/${pkgName}/package.json`,
            package: pkgName,
            version: pkg.version,
            script: scriptName,
            value: scriptValue,
            patternId: pattern.id,
            description: pattern.description,
            explanation: pattern.explanation,
          });
        }
      }
    }
  }

  return findings;
}