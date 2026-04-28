const COMPOSITE_RULES = [
  {
    id: "obfuscated-execution",
    signals: ["base64-decode-exec", "eval-obfuscated"],
    bonus: 15,
    severity: "critical",
    description: "Patrón de ejecución ofuscada detectado",
  },
  {
    id: "env-exfiltration",
    signals: ["process-env-exfil", "fetch-external"],
    bonus: 20,
    severity: "critical",
    description: "Posible exfiltración de variables de entorno",
  },
  {
    id: "persistence-mechanism",
    signals: ["bashrc-modification", "cron-persistence"],
    bonus: 25,
    severity: "critical",
    description: "Mecanismo de persistencia detectado",
  },
  {
    id: "reverse-shell-setup",
    signals: ["reverse-shell", "child-process-exec"],
    bonus: 20,
    severity: "critical",
    description: "Configuración de reverse shell detectada",
  },
]

function detectMultiMatch(findings) {
  const byFile = {}
  for (const f of findings) {
    const file = f.file || f.package || "unknown"
    if (!byFile[file]) byFile[file] = []
    byFile[file].push(f.patternId)
  }

  const multiMatches = []
  for (const [file, patternIds] of Object.entries(byFile)) {
    const uniquePatterns = new Set(patternIds)
    if (uniquePatterns.size >= 3) {
      multiMatches.push({
        id: "multi-pattern-file",
        file,
        patterns: Array.from(uniquePatterns),
        severity: "high",
        bonus: 10,
        description: `Archivo con ${uniquePatterns.size} patrones sospechosos: ${Array.from(uniquePatterns).join(", ")}`,
      })
    }
  }

  return multiMatches
}

function detectComposites(findings) {
  const foundIds = new Set(findings.map(f => f.patternId))
  const composites = []

  for (const rule of COMPOSITE_RULES) {
    const matched = rule.signals.every(s => foundIds.has(s))
    if (matched) {
      composites.push({
        id: rule.id,
        bonus: rule.bonus,
        severity: rule.severity,
        description: rule.description,
        composite: true,
        signals: rule.signals,
      })
    }
  }

  const multiMatches = detectMultiMatch(findings)
  for (const mm of multiMatches) {
    composites.push(mm)
  }

  return composites
}

export { COMPOSITE_RULES, detectComposites }