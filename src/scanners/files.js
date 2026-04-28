import { readFileSync, readdirSync, statSync, existsSync } from "fs";
import path from "path";
import { patterns } from "../patterns/index.js";
const SKIP_DIRS = new Set([
  ".git", ".svn", "dist", "build", "coverage",
  "__tests__", "__mocks__", ".cache", ".turbo", "node_modules",
]);


const SOURCE_EXTENSIONS = new Set([".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"]);
function getPackageEntryFiles(pkgPath) {
  const pkgJsonPath = path.join(pkgPath, "package.json");
  if (!existsSync(pkgJsonPath)) return [];
  let pkg;
  try {
    pkg = JSON.parse(readFileSync(pkgJsonPath, "utf8"));
  } catch {
    return [];
  }
  const entries = new Set();
  for (const field of ["main", "module", "exports"]) {
    if (typeof pkg[field] === "string") {
      const fullPath = path.join(pkgPath, pkg[field]);
      if (existsSync(fullPath)) entries.add(fullPath);
    }
  }
  return [...entries];
}
function scanFile(filePath) {
  const findings = [];
  let content;
  try {
    content = readFileSync(filePath, "utf8");
  } catch {
    return findings;
  }
  const lines = content.split("\n");
  for (const pattern of patterns) {
    for (let i = 0; i < lines.length; i++) {
      if (pattern.regex.test(lines[i])) {
        findings.push({
          type: "source-code",
          severity: pattern.severity,
          category: pattern.category,
          file: filePath,
          line: i + 1,
          lineContent: lines[i].trim(),
          patternId: pattern.id,
          description: pattern.description,
          explanation: pattern.explanation,
        });
      }
    }
  }
  return findings;
}
function walkDirectory(dirPath, maxDepth = 5, currentDepth = 0) {
  const files = [];
  if (currentDepth > maxDepth) return files;
  let entries;
  try {
    entries = readdirSync(dirPath);
  } catch {
    return files;
  }
  for (const entry of entries) {
    if (SKIP_DIRS.has(entry)) continue;
    const fullPath = path.join(dirPath, entry);
    let stat;
    try {
      stat = statSync(fullPath);
    } catch {
      continue;
    }
    if (stat.isDirectory()) {
      files.push(...walkDirectory(fullPath, maxDepth, currentDepth + 1));
    } else if (SOURCE_EXTENSIONS.has(path.extname(entry))) {
      files.push(fullPath);
    }
  }
  return files;
}
export function scanSourceCode(projectPath) {
  const findings = [];
  const srcDirs = ["src", "lib", "app", "index.js", "index.ts"].map((d) =>
    path.join(projectPath, d)
  );
  const filesToScan = [];
  for (const dir of srcDirs) {
    if (!existsSync(dir)) continue;
    const stat = statSync(dir);
    if (stat.isFile()) {
      filesToScan.push(dir);
    } else if (stat.isDirectory()) {
      filesToScan.push(...walkDirectory(dir));
    }
  }
  if (filesToScan.length === 0) {
    filesToScan.push(...walkDirectory(projectPath, 1));
  }
  for (const file of filesToScan) {
    findings.push(...scanFile(file));
  }
  return findings;
}
export function scanNodeModulesFiles(projectPath, onProgress) {
  const findings = [];
  const nodeModulesPath = path.join(projectPath, "node_modules");
  if (!existsSync(nodeModulesPath)) return findings;
  let packages;
  try {
    packages = readdirSync(nodeModulesPath).filter(
      (e) => !e.startsWith(".")
    );
  } catch {
    return findings;
  }
  let scanned = 0;
  const total = packages.length;
  for (const pkgName of packages) {
    const pkgPath = path.join(nodeModulesPath, pkgName);
    let stat;
    try {
      stat = statSync(pkgPath);
    } catch {
      continue;
    }
    if (!stat.isDirectory()) continue;
    if (pkgName.startsWith("@")) {
      try {
        const scopedPkgs = readdirSync(pkgPath);
        for (const scopedPkg of scopedPkgs) {
          const scopedPath = path.join(pkgPath, scopedPkg);
          const entryFiles = getPackageEntryFiles(scopedPath);
          for (const file of entryFiles) {
            findings.push(...scanFile(file));
          }
        }
      } catch {
        continue;
      }
    } else {
      const entryFiles = getPackageEntryFiles(pkgPath);
      for (const file of entryFiles) {
        findings.push(...scanFile(file));
      }
    }
    scanned++;
    if (onProgress) onProgress(scanned, total);
  }
  return findings;
}