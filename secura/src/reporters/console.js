import chalk from "chalk";
import { writeFileSync, existsSync } from "fs";

const SEVERITY_CONFIG = {
  critical: { icon: "☠️", label: "CRÍTICO", color: chalk.red.bold.underline },
  high: { icon: "🔴", label: "ALTO", color: chalk.red.bold },
  medium: { icon: "⚠️ ", label: "MEDIO", color: chalk.yellow.bold },
  low: { icon: "🔵", label: "BAJO", color: chalk.blue },
};

const CATEGORY_LABELS = {
  "code-execution": "Ejecución de código",
  "data-exfiltration": "Exfiltración de datos",
  "network": "Red / Comunicación externa",
  "system-execution": "Ejecución del sistema",
  "obfuscation": "Ofuscación",
  "credentials": "Credenciales / Keys",
  "malware": "Malware / Mining",
};

export function printBanner() {
  console.log(chalk.cyan.bold(`
  ███████╗███████╗ ██████╗██╗   ██╗██████╗  █████╗
  ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔══██╗
  ███████╗█████╗  ██║     ██║   ██║██████╔╝███████║
  ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══██║
  ███████║███████╗╚██████╗╚██████╔╝██║  ██║██║  ██║
  ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝
  `));
  console.log(chalk.gray("  Security scanner for Node.js projects\n"));
}

export function printPhaseHeader(title) {
  console.log(chalk.cyan(`\n▶ ${title}`));
  console.log(chalk.gray("─".repeat(60)));
}

export function printProgress(current, total) {
  const pct = Math.round((current / total) * 100);
  process.stdout.write(
    `\r  ${chalk.gray(`Escaneando paquetes... ${current}/${total} (${pct}%)`)}`
  );
}

export function printFindings(findings, label) {
  if (findings.length === 0) {
    console.log(chalk.green(`  ✅ Sin hallazgos sospechosos`));
    return;
  }

  const grouped = {};
  for (const f of findings) {
    const key = f.package ? `${f.package}@${f.version}` : f.file;
    if (!grouped[key]) grouped[key] = [];
    grouped[key].push(f);
  }

  for (const [group, groupFindings] of Object.entries(grouped)) {
    const severityOrder = { critical: 3, high: 2, medium: 1, low: 0 };
    const maxSeverity = groupFindings.reduce((max, f) => 
      severityOrder[f.severity] > severityOrder[max] ? f.severity : max, 
      "low"
    );

    const cfg = SEVERITY_CONFIG[maxSeverity];
    console.log(`\n  ${cfg.icon} ${cfg.color(group)}`);

    for (const f of groupFindings) {
      const fcfg = SEVERITY_CONFIG[f.severity];
      console.log(
        `     ${fcfg.color(`[${fcfg.label}]`)} ${chalk.white(f.description)}`
      );

      if (f.type === "source-code") {
        console.log(
          `     ${chalk.gray(`→ línea ${f.line}:`)} ${chalk.yellow(f.lineContent)}`
        );
      } else if (f.script) {
        console.log(
          `     ${chalk.gray(`→ script '${f.script}':`)} ${chalk.yellow(f.value)}`
        );
      }

      console.log(chalk.gray(`     💡 ${f.explanation}`));
    }
  }
}

export function printAIAnalysis(analysis) {
  if (!analysis) return;

  console.log(chalk.cyan("\n\n▶ Análisis de IA"));
  console.log(chalk.gray("─".repeat(60)));
  console.log(chalk.cyan("🤖 Análisis:\n"));

  const lines = analysis.split("\n");
  for (const line of lines) {
    console.log(`  ${line}`);
  }
}

export function printSummary(allFindings, duration) {
  const critical = allFindings.filter((f) => f.severity === "critical").length;
  const high = allFindings.filter((f) => f.severity === "high").length;
  const medium = allFindings.filter((f) => f.severity === "medium").length;
  const low = allFindings.filter((f) => f.severity === "low").length;

  console.log(chalk.cyan("\n\n▶ Resumen"));
  console.log(chalk.gray("─".repeat(60)));
  console.log(
    `  ${chalk.red.bold.underline(`☠️ Crítico: ${critical}`)}   ` +
    `${chalk.red.bold(`🔴 Alto: ${high}`)}   ` +
    `${chalk.yellow.bold(`⚠️  Medio: ${medium}`)}   ` +
    `${chalk.blue(`🔵 Bajo: ${low}`)}`
  );
  console.log(chalk.gray(`\n  Tiempo: ${duration}ms`));

  if (critical > 0) {
    console.log(
      chalk.red.bold.underline("\n  ☠️  CRÍTICO: Hallazgos extremadamente graves detectados.")
    );
  } else if (high > 0) {
    console.log(
      chalk.red.bold("\n  ⛔ Se encontraron hallazgos de severidad ALTA.")
    );
  } else if (medium > 0) {
    console.log(chalk.yellow("\n  ⚠️  Se encontraron hallazgos de severidad media."));
  } else if (low > 0) {
    console.log(chalk.blue("\n  🔵 Solo hallazgos de baja severidad."));
  } else {
    console.log(chalk.green.bold("\n  ✅ ¡Todo limpio!"));
  }

  console.log();
}

export function exportJSON(allFindings, outputPath) {
  const report = {
    generatedAt: new Date().toISOString(),
    totalFindings: allFindings.length,
    bySeverity: {
      critical: allFindings.filter((f) => f.severity === "critical").length,
      high: allFindings.filter((f) => f.severity === "high").length,
      medium: allFindings.filter((f) => f.severity === "medium").length,
      low: allFindings.filter((f) => f.severity === "low").length,
    },
    findings: allFindings,
  };
  writeFileSync(outputPath, JSON.stringify(report, null, 2));
  console.log(chalk.gray(`\n  📄 Reporte exportado a: ${outputPath}`));
}

export function printEnvironmentAudit(audit) {
  console.log(chalk.cyan(`\n\n▶ 🛡️ Diagnóstico de entorno`));
  console.log(chalk.gray("─".repeat(60)));
  
  const pmIcon = audit.packageManager === "pnpm" ? "✅" : "⚠️ ";
  console.log(`  📦 Package Manager: ${pmIcon}${audit.packageManager}`);
  
  if (audit.packageManager !== "pnpm") {
    console.log(chalk.gray(`     → Recomendado: pnpm (mejores defaults de seguridad)`));
  }
  
  console.log(chalk.gray("\n  🔧 Configuraciones detectadas:"));
  
  if (audit.recommendations.length === 0) {
    console.log(chalk.green("     ✅ Todas las configuraciones recomendadas activas"));
  } else {
    const highPriority = audit.recommendations.filter(r => r.severity === "high");
    const mediumPriority = audit.recommendations.filter(r => r.severity === "medium");
    const lowPriority = audit.recommendations.filter(r => r.severity === "low");
    
    for (const rec of highPriority) {
      const current = rec.currentValue === "not set" ? "not set" : rec.currentValue;
      console.log(`     ${chalk.red("❌")} ${rec.key}: ${chalk.yellow(current)} → ${chalk.green(rec.recommendedValue)}`);
      console.log(chalk.gray(`        ${rec.description}`));
    }
    
    for (const rec of mediumPriority) {
      const current = rec.currentValue === "not set" ? "not set" : rec.currentValue;
      console.log(`     ${chalk.yellow("⚠️ ")} ${rec.key}: ${chalk.yellow(current)} → ${chalk.green(rec.recommendedValue)}`);
    }
    
    for (const rec of lowPriority) {
      const current = rec.currentValue === "not set" ? "not set" : rec.currentValue;
      console.log(`     ${chalk.blue("🔵")} ${rec.key}: ${chalk.yellow(current)} → ${chalk.green(rec.recommendedValue)}`);
    }
  }
}

export function printGitignoreAudit(audit) {
  console.log(chalk.cyan(`\n\n▶ 📄 Análisis de .gitignore`));
  console.log(chalk.gray("─".repeat(60)));
  
  if (!audit.exists) {
    console.log(chalk.red("  ❌ .gitignore no existe"));
  } else {
    console.log(chalk.green(`  ✅ .gitignore existe (${audit.present.length} patrones)`));
  }
  
  if (audit.missing.length > 0) {
    console.log(chalk.gray("\n  📁 Archivos sensibles sin ignorar:"));
    const critical = audit.missing.filter(f => f.severity === "critical");
    const high = audit.missing.filter(f => f.severity === "high");
    const other = audit.missing.filter(f => f.severity !== "critical" && f.severity !== "high");
    
    for (const file of [...critical, ...high, ...other].slice(0, 10)) {
      const icon = file.severity === "critical" ? "☠️" : file.severity === "high" ? "🔴" : "⚠️ ";
      console.log(`     ${icon} ${file.pattern}`);
      console.log(chalk.gray(`        ${file.description}`));
    }
    
    if (audit.missing.length > 10) {
      console.log(chalk.gray(`     ... y ${audit.missing.length - 10} más`));
    }
  }
  
  if (audit.dangerous.length > 0) {
    console.log(chalk.gray("\n  ⚠️  Patrones potencialmente peligrosos:"));
    for (const d of audit.dangerous) {
      console.log(`     ${chalk.yellow("⚠️ ")} ${d.pattern}`);
      console.log(chalk.gray(`        ${d.reason}`));
    }
  }
}

export function printHardeningPrompt() {
  console.log(chalk.cyan("\n\n────────────────────────────────────────────────────────────"));
  console.log(chalk.white("  ¿Aplicar hardening automático? (S/N): "));
}

export function printHardeningResults(results) {
  console.log(chalk.cyan("\n\n▶ 🔧 Resultados del hardening"));
  console.log(chalk.gray("─".repeat(60)));
  
  if (results.npmrc) {
    console.log(chalk.green("  ✅ .npmrc actualizado"));
    if (results.npmrc.applied.length > 0) {
      console.log(chalk.gray(`     Nuevas configs: ${results.npmrc.applied.join(", ")}`));
    }
    if (results.npmrc.updated.length > 0) {
      console.log(chalk.gray(`     Actualizadas: ${results.npmrc.updated.join(", ")}`));
    }
  }
  
  if (results.gitignore) {
    console.log(chalk.green("  ✅ .gitignore actualizado"));
    console.log(chalk.gray(`     ${results.gitignore.added.length} patrones agregados`));
  }
  
  if (results.errors.length > 0) {
    console.log(chalk.red("  ❌ Errores:"));
    for (const err of results.errors) {
      console.log(chalk.gray(`     - ${err}`));
    }
  }
  
  console.log(chalk.green("\n  🎉 Hardening aplicado exitosamente!"));
}