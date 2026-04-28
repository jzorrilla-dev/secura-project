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

  return composites
}

export { COMPOSITE_RULES, detectComposites }