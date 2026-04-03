#!/usr/bin/env node

import { program } from "commander";
import chalk from "chalk";
import path from "path";
import { existsSync } from "fs";
import readline from "readline";

import { scanPackageJson } from "./scanners/scripts.js";
import { scanSourceCode, scanNodeModulesFiles } from "./scanners/files.js";
import { analyzeWithAI, isOllamaAvailable, getAvailableProviders } from "./utils/ai.js";
import { auditEnvironment } from "./auditors/environment.js";
import { auditGitignore } from "./auditors/gitignore.js";
import { applyHardening } from "./hardening/apply.js";
import {
  printBanner,
  printPhaseHeader,
  printFindings,
  printProgress,
  printAIAnalysis,
  printSummary,
  exportJSON,
  printEnvironmentAudit,
  printGitignoreAudit,
  printHardeningPrompt,
  printHardeningResults,
} from "./reporters/console.js";

program
  .name("secura")
  .description("Security scanner for Node.js projects")
  .version("0.1.0")
  .option("--mcp", "Iniciar en modo servidor MCP (stdio)")
  .argument("[path]", "Ruta del proyecto a escanear", ".")
  .option("--no-ai", "Desactivar análisis con IA")
  .option("--ai-provider <provider>", "Proveedor de IA: groq | ollama | auto", "auto")
  .option("--json [file]", "Exportar reporte en JSON", "secura-report.json")
  .option("--only <phase>", "Escanear solo una fase: scripts | source | modules")
  .option("--audit-env", "Incluir diagnóstico de entorno")
  .option("--skip-gitignore", "No analizar .gitignore")
  .option("--apply", "Aplicar hardening automáticamente sin preguntar")
  .option("--pm <manager>", "Forzar package manager: npm, yarn, pnpm")
  .parse();

const options = program.opts();
const targetPath = path.resolve(program.args[0] || ".");

function promptHardening() {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });
    
    rl.question("", (answer) => {
      rl.close();
      resolve(answer.toLowerCase().trim());
    });
  });
}

async function main() {
  if (options.mcp) {
    const { spawn } = await import("child_process");
    const serverPath = process.cwd() + "/mcp-server.js";
    const child = spawn("node", [serverPath], {
      stdio: "inherit",
    });
    child.on("close", (code) => process.exit(code));
    return;
  }

  const startTime = Date.now();

  printBanner();

  if (!existsSync(targetPath)) {
    console.error(`❌ No se encontró el directorio: ${targetPath}`);
    process.exit(1);
  }

  const projectName = path.basename(targetPath);
  console.log(`  Escaneando: ${targetPath}\n`);

  const allFindings = [];

  if (!options.only || options.only === "scripts") {
    printPhaseHeader("📦 package.json — Scripts de lifecycle");
    const scriptFindings = scanPackageJson(targetPath);
    printFindings(scriptFindings, "Scripts");
    allFindings.push(...scriptFindings);
  }

  if (!options.only || options.only === "source") {
    printPhaseHeader("💻 Código fuente");
    const sourceFindings = scanSourceCode(targetPath);
    printFindings(sourceFindings, "Código fuente");
    allFindings.push(...sourceFindings);
  }

  if (!options.only || options.only === "modules") {
    printPhaseHeader("📁 node_modules — Archivos de entrada de paquetes");

    const moduleFindings = scanNodeModulesFiles(targetPath, (current, total) => {
      printProgress(current, total);
    });

    process.stdout.write("\n");
    printFindings(moduleFindings, "node_modules");
    allFindings.push(...moduleFindings);
  }

  if (options.ai !== false) {
    const ollamaReady = await isOllamaAvailable();
    const groqKey = process.env.GROQ_API_KEY;
    const providers = [];
    if (ollamaReady) providers.push("ollama");
    if (groqKey) providers.push("groq");

    if (providers.length === 0) {
      console.log(
        `\n  ${chalk.yellow("⚠️  No hay proveedor de IA disponible")}`
      );
      console.log(`     Configurá GROQ_API_KEY o instalá Ollama: https://ollama.com\n`);
    } else {
      printPhaseHeader("🤖 Analizando hallazgos con IA...");
      console.log(chalk.gray(`  → Proveedores disponibles: ${providers.join(", ")}`));
      try {
        const analysis = await analyzeWithAI(allFindings, projectName, options.aiProvider);
        printAIAnalysis(analysis);
      } catch (err) {
        console.log(chalk.yellow(`  ⚠️  Error con IA: ${err.message}`));
      }
    }
  }

  const duration = Date.now() - startTime;
  printSummary(allFindings, duration);

  if (options.auditEnv) {
    const packageManager = options.pm || "auto";
    const envAudit = auditEnvironment(targetPath);
    const pm = packageManager === "auto" ? envAudit.packageManager : packageManager;
    
    printEnvironmentAudit(envAudit);
    
    if (!options.skipGitignore) {
      const gitignoreAudit = auditGitignore(targetPath);
      printGitignoreAudit(gitignoreAudit);
    }
    
    if (options.apply) {
      const results = applyHardening(targetPath, pm);
      printHardeningResults(results);
    } else {
      const hasRecommendations = envAudit.recommendations.length > 0 || 
        (!options.skipGitignore && auditGitignore(targetPath).missing.length > 0);
      
      if (hasRecommendations) {
        printHardeningPrompt();
        const answer = await promptHardening();
        
        if (answer === "s" || answer === "si" || answer === "y" || answer === "yes") {
          const results = applyHardening(targetPath, pm);
          printHardeningResults(results);
        } else {
          console.log(chalk.gray("\n  Saltando hardening. Podés aplicarlo manualmente luego."));
        }
      }
    }
  }

  if (options.json) {
    const outputPath =
      typeof options.json === "string" ? options.json : "secura-report.json";
    await exportJSON(allFindings, outputPath);
  }

  const hasHighOrCritical = allFindings.some((f) => 
    f.severity === "critical" || f.severity === "high"
  );
  process.exit(hasHighOrCritical ? 1 : 0);
}

main().catch((err) => {
  console.error("Error inesperado:", err);
  process.exit(1);
});