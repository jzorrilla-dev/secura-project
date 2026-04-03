import { readFileSync, writeFileSync, existsSync } from "fs";
import path from "path";
import { getRecommendedNpmrc } from "../auditors/environment.js";
import { generateGitignoreRecommendations, readGitignore } from "../auditors/gitignore.js";

function readNpmrc(projectPath) {
  const npmrcPath = path.join(projectPath, ".npmrc");
  if (existsSync(npmrcPath)) {
    try {
      return readFileSync(npmrcPath, "utf8");
    } catch {
      return "";
    }
  }
  return "";
}

function parseNpmrc(content) {
  const configs = {};
  const lines = content.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith("#")) {
      const [key, ...valueParts] = trimmed.split("=");
      if (key) {
        configs[key.trim()] = valueParts.join("=").trim();
      }
    }
  }
  return configs;
}

function serializeNpmrc(configs) {
  return Object.entries(configs)
    .map(([key, value]) => `${key}=${value}`)
    .join("\n") + "\n";
}

export function applyNpmrcHardening(projectPath, packageManager) {
  const npmrcPath = path.join(projectPath, ".npmrc");
  const currentContent = readNpmrc(projectPath);
  const currentConfigs = parseNpmrc(currentContent);
  const recommended = getRecommendedNpmrc(packageManager);
  
  const newConfigs = { ...currentConfigs, ...recommended };
  const newContent = serializeNpmrc(newConfigs);
  
  writeFileSync(npmrcPath, newContent);
  
  return {
    applied: Object.keys(recommended).filter(k => !currentConfigs[k]),
    updated: Object.keys(recommended).filter(k => currentConfigs[k] !== recommended[k]),
  };
}

export function applyGitignoreHardening(projectPath) {
  const gitignorePath = path.join(projectPath, ".gitignore");
  const current = readGitignore(projectPath);
  const recommendations = generateGitignoreRecommendations(current.patterns);
  
  let newContent = "";
  
  if (current.exists) {
    const existingContent = readFileSync(gitignorePath, "utf8");
    const header = existingContent.includes("# Secrets") 
      ? existingContent 
      : existingContent + "\n\n# Secrets\n";
    
    const newPatterns = recommendations.map(p => p.replace(/\*/g, "")).join("\n");
    newContent = header + newPatterns + "\n";
  } else {
    newContent = `# Secrets
${recommendations.map(p => p.replace(/\*/g, "")).join("\n")}
# Dependencies
node_modules/
# Build outputs
dist/
build/
# Logs
*.log
npm-debug.log*
yarn-error.log
# IDE
.idea/
.vscode/
.DS_Store
`;
  }
  
  writeFileSync(gitignorePath, newContent);
  
  return {
    added: recommendations,
    total: recommendations.length,
  };
}

export function applyEngineStrict(projectPath) {
  const pkgPath = path.join(projectPath, "package.json");
  if (!existsSync(pkgPath)) return { success: false, reason: "No package.json" };
  
  try {
    const pkg = JSON.parse(readFileSync(pkgPath, "utf8"));
    pkg.engineStrict = false;
    
    writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
    return { success: true };
  } catch (err) {
    return { success: false, reason: err.message };
  }
}

export function applyHardening(projectPath, packageManager, options = {}) {
  const results = {
    npmrc: null,
    gitignore: null,
    packageJson: null,
    errors: [],
  };
  
  try {
    if (options.npmrc !== false) {
      results.npmrc = applyNpmrcHardening(projectPath, packageManager);
    }
  } catch (err) {
    results.errors.push(`npmrc: ${err.message}`);
  }
  
  try {
    if (options.gitignore !== false) {
      results.gitignore = applyGitignoreHardening(projectPath);
    }
  } catch (err) {
    results.errors.push(`gitignore: ${err.message}`);
  }
  
  try {
    if (options.engineStrict !== false) {
      results.packageJson = applyEngineStrict(projectPath);
    }
  } catch (err) {
    results.errors.push(`package.json: ${err.message}`);
  }
  
  return results;
}