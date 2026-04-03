import { readFileSync, existsSync } from "fs";
import path from "path";

const SECURITY_CONFIGS = [
  {
    key: "ignore-scripts",
    recommended: "true",
    severity: "high",
    description: "Previene ejecución de scripts maliciosos en postinstall",
    category: "script-security"
  },
  {
    key: "audit-level",
    recommended: "high",
    severity: "high",
    description: "Alerta sobre vulnerabilidades de severidad alta",
    category: "vulnerability-detection"
  },
  {
    key: "fund",
    recommended: "false",
    severity: "medium",
    description: "Desactiva mensajes de donation de npm",
    category: "privacy"
  },
  {
    key: "engine-strict",
    recommended: "false",
    severity: "low",
    description: "Exige versiones exactas de Node matching engines",
    category: "compatibility"
  },
  {
    key: "legacy-peer-deps",
    recommended: "false",
    severity: "medium",
    description: "Evita que conflictos de peer deps se ignoren",
    category: "compatibility"
  },
  {
    key: "audit",
    recommended: "true",
    severity: "medium",
    description: "Ejecuta npm audit automáticamente",
    category: "vulnerability-detection"
  },
];

const RECOMMENDED_CONFIGS = {
  pnpm: {
    "ignore-scripts": "true",
    "engine-strict": "false",
    "public-hoist-pattern": "[]",
  },
  npm: {
    "ignore-scripts": "true",
    "audit-level": "high",
    "fund": "false",
    "audit": "true",
    "engine-strict": "false",
    "legacy-peer-deps": "false",
  },
  yarn: {
    "ignore-scripts": "true",
    "engine-strict": "false",
  }
};

function detectPackageManager(projectPath) {
  if (existsSync(path.join(projectPath, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(path.join(projectPath, "yarn.lock"))) return "yarn";
  if (existsSync(path.join(projectPath, "package-lock.json"))) return "npm";
  return "unknown";
}

function readNpmrc(projectPath) {
  const configs = {};
  
  const npmrcPaths = [
    path.join(projectPath, ".npmrc"),
    path.join(process.env.HOME || "", ".npmrc"),
    path.join(process.env.HOME || "", ".config", "npmrc"),
  ];
  
  for (const npmrcPath of npmrcPaths) {
    if (existsSync(npmrcPath)) {
      try {
        const content = readFileSync(npmrcPath, "utf8");
        const lines = content.split("\n");
        for (const line of lines) {
          const trimmed = line.trim();
          if (trimmed && !trimmed.startsWith("#")) {
            const [key, ...valueParts] = trimmed.split("=");
            if (key && valueParts.length > 0) {
              configs[key.trim()] = valueParts.join("=").trim();
            }
          }
        }
      } catch {}
    }
  }
  
  return configs;
}

function readPackageJson(projectPath) {
  const pkgPath = path.join(projectPath, "package.json");
  if (!existsSync(pkgPath)) return {};
  
  try {
    return JSON.parse(readFileSync(pkgPath, "utf8"));
  } catch {
    return {};
  }
}

function analyzeConfigs(configs, packageManager) {
  const findings = [];
  const recommended = RECOMMENDED_CONFIGS[packageManager] || RECOMMENDED_CONFIGS.npm;
  
  for (const [key, recommendedValue] of Object.entries(recommended)) {
    const currentValue = configs[key];
    
    if (currentValue === undefined) {
      findings.push({
        type: "missing-config",
        key,
        currentValue: "not set",
        recommendedValue,
        severity: SECURITY_CONFIGS.find(c => c.key === key)?.severity || "medium",
        description: SECURITY_CONFIGS.find(c => c.key === key)?.description || "",
      });
    } else if (currentValue !== recommendedValue) {
      findings.push({
        type: "mismatch-config",
        key,
        currentValue,
        recommendedValue,
        severity: SECURITY_CONFIGS.find(c => c.key === key)?.severity || "medium",
        description: SECURITY_CONFIGS.find(c => c.key === key)?.description || "",
      });
    }
  }
  
  return findings;
}

export function auditEnvironment(projectPath) {
  const findings = {
    packageManager: detectPackageManager(projectPath),
    configs: readNpmrc(projectPath),
    packageJson: readPackageJson(projectPath),
    recommendations: [],
  };
  
  findings.recommendations = analyzeConfigs(findings.configs, findings.packageManager);
  
  return findings;
}

export function getRecommendedNpmrc(packageManager) {
  return RECOMMENDED_CONFIGS[packageManager] || RECOMMENDED_CONFIGS.npm;
}