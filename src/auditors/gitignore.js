import { readFileSync, existsSync } from "fs";
import path from "path";

const SENSITIVE_FILES = [
  { pattern: ".env", description: "Variables de entorno con secrets", severity: "high" },
  { pattern: ".env.local", description: "Variables de entorno locales", severity: "high" },
  { pattern: ".env.*.local", description: "Variables de entorno por entorno", severity: "high" },
  { pattern: ".npmrc", description: "Configuración de npm (puede contener tokens)", severity: "high" },
  { pattern: ".yarnrc", description: "Configuración de yarn (puede contener tokens)", severity: "high" },
  { pattern: "*.pem", description: "Certificados SSL/TLS", severity: "high" },
  { pattern: "*.key", description: "Claves privadas", severity: "high" },
  { pattern: "*.crt", description: "Certificados", severity: "high" },
  { pattern: "id_rsa", description: "Clave SSH privada", severity: "critical" },
  { pattern: "id_ed25519", description: "Clave SSH ED25519", severity: "critical" },
  { pattern: "known_hosts", description: "Hosts conocidos de SSH (puede filtrar IPs)", severity: "medium" },
  { pattern: "credentials.json", description: "Credenciales Google/AWS", severity: "critical" },
  { pattern: "secrets.json", description: "Secrets generales", severity: "critical" },
  { pattern: "service-account.json", description: "Credenciales GCP", severity: "critical" },
  { pattern: ".aws/credentials", description: "Credenciales AWS", severity: "critical" },
  { pattern: ".aws/config", description: "Configuración AWS", severity: "medium" },
  { pattern: ".pki", description: "Certificados del sistema", severity: "high" },
  { pattern: "*.log", description: "Archivos de log", severity: "low" },
  { pattern: "npm-debug.log*", description: "Logs de npm", severity: "low" },
  { pattern: "yarn-error.log", description: "Logs de yarn", severity: "low" },
  { pattern: ".DS_Store", description: "Archivos de macOS", severity: "low" },
  { pattern: "Thumbs.db", description: "Archivos de Windows", severity: "low" },
];

const DANGEROUS_PATTERNS = [
  { pattern: "node_modules/", action: "keep", reason: "Necesario para desarrollo" },
  { pattern: "dist/", action: "keep", reason: "Build output" },
  { pattern: "build/", action: "keep", reason: "Build output" },
];

export function readGitignore(projectPath) {
  const gitignorePath = path.join(projectPath, ".gitignore");
  
  if (!existsSync(gitignorePath)) {
    return { exists: false, patterns: [] };
  }
  
  try {
    const content = readFileSync(gitignorePath, "utf8");
    const patterns = content
      .split("\n")
      .map(line => line.trim())
      .filter(line => line && !line.startsWith("#"));
    
    return { exists: true, patterns };
  } catch {
    return { exists: false, patterns: [] };
  }
}

export function auditGitignore(projectPath) {
  const gitignore = readGitignore(projectPath);
  
  const findings = {
    exists: gitignore.exists,
    missing: [],
    present: [],
    dangerous: [],
  };
  
  if (!gitignore.exists) {
    for (const file of SENSITIVE_FILES) {
      findings.missing.push({
        ...file,
        reason: ".gitignore no existe o no contiene este patrón",
      });
    }
    return findings;
  }
  
  for (const file of SENSITIVE_FILES) {
    const isPresent = gitignore.patterns.some(pattern => {
      const normalizedPattern = pattern.replace(/\/$/, "").replace(/^\*/, "*");
      return normalizedPattern === file.pattern || 
             normalizedPattern === `*${file.pattern}` ||
             pattern.includes(file.pattern);
    });
    
    if (isPresent) {
      findings.present.push(file.pattern);
    } else {
      findings.missing.push({
        ...file,
        reason: "Patrón no encontrado en .gitignore",
      });
    }
  }
  
  for (const pattern of gitignore.patterns) {
    const isDangerous = DANGEROUS_PATTERNS.some(d => 
      d.pattern === pattern && d.action === "remove"
    );
    if (isDangerous) {
      findings.dangerous.push({
        pattern,
        reason: DANGEROUS_PATTERNS.find(d => d.pattern === pattern)?.reason || "",
      });
    }
  }
  
  return findings;
}

export function generateGitignoreRecommendations(currentPatterns) {
  const recommendations = [];
  
  for (const file of SENSITIVE_FILES) {
    const isPresent = currentPatterns.some(pattern => 
      pattern === file.pattern || pattern.includes(file.pattern)
    );
    
    if (!isPresent) {
      recommendations.push(file.pattern);
    }
  }
  
  return recommendations;
}