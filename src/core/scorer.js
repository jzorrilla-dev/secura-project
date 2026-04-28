import {
  SEVERITY_SCORES,
  CONFIDENCE_MULTIPLIERS,
  RISK_THRESHOLDS,
  calculateFindingScore,
  getRiskLevel,
} from "../patterns/index.js"
import { detectComposites } from "./composites.js"

function deduplicateFindings(findings) {
  const seen = new Set()
  const unique = []
  for (const f of findings) {
    const key = `${f.patternId}:${f.file || f.package}:${f.line || "script"}`
    if (!seen.has(key)) {
      seen.add(key)
      unique.push(f)
    }
  }
  return unique
}

function calculateProjectScore(findings) {
  if (!findings || findings.length === 0) {
    return {
      totalScore: 0,
      baseScore: 0,
      compositeScore: 0,
      riskLevel: "LOW",
      findingsCount: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: {},
      uniquePatterns: 0,
      composites: [],
    }
  }

  const uniqueFindings = deduplicateFindings(findings)
  const uniquePatterns = new Set(uniqueFindings.map(f => f.patternId)).size

  let baseScore = 0
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 }
  const byCategory = {}
  const patternCounts = {}

  for (const finding of uniqueFindings) {
    patternCounts[finding.patternId] = (patternCounts[finding.patternId] || 0) + 1
  }

  for (const finding of uniqueFindings) {
    const base = calculateFindingScore(finding)
    const count = patternCounts[finding.patternId]
    const weight = Math.log(1 + count)
    const score = base * weight
    baseScore += score

    bySeverity[finding.severity]++
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1
  }

  const composites = detectComposites(uniqueFindings)
  const compositeScore = composites.reduce((acc, c) => acc + c.bonus, 0)
  const totalScore = baseScore + compositeScore

  let riskLevel = getRiskLevel(totalScore)
  if (bySeverity.critical > 0) {
    riskLevel = "CRITICAL"
  } else if (bySeverity.high > 0 && riskLevel === "LOW") {
    riskLevel = "HIGH"
  } else if (bySeverity.medium > 0 && riskLevel === "LOW") {
    riskLevel = "MEDIUM"
  }

  return {
    totalScore: Math.round(totalScore * 10) / 10,
    baseScore: Math.round(baseScore * 10) / 10,
    compositeScore,
    riskLevel,
    findingsCount: findings.length,
    uniqueFindings: uniqueFindings.length,
    uniquePatterns,
    bySeverity,
    byCategory,
    composites,
  }
}

export function scoreFindings(findings) {
  return calculateProjectScore(findings)
}

export {
  SEVERITY_SCORES,
  CONFIDENCE_MULTIPLIERS,
  RISK_THRESHOLDS,
  calculateFindingScore,
  getRiskLevel,
  calculateProjectScore,
}