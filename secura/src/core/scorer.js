import {
  SEVERITY_SCORES,
  CONFIDENCE_MULTIPLIERS,
  RISK_THRESHOLDS,
  calculateFindingScore,
  getRiskLevel,
} from "../patterns/index.js"
import { detectComposites } from "./composites.js"

export function calculateProjectScore(findings) {
  if (!findings || findings.length === 0) {
    return {
      totalScore: 0,
      baseScore: 0,
      compositeScore: 0,
      riskLevel: "LOW",
      findingsCount: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: {},
      composites: [],
    }
  }

  let baseScore = 0
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 }
  const byCategory = {}
  const scoredFindings = []

  for (const finding of findings) {
    const score = calculateFindingScore(finding)
    baseScore += score

    bySeverity[finding.severity]++
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1

    scoredFindings.push({ ...finding, score })
  }

  const composites = detectComposites(findings)
  const compositeScore = composites.reduce((acc, c) => acc + c.bonus, 0)
  const totalScore = baseScore + compositeScore
  const riskLevel = getRiskLevel(totalScore)

  return {
    totalScore: Math.round(totalScore * 10) / 10,
    baseScore: Math.round(baseScore * 10) / 10,
    compositeScore,
    riskLevel,
    findingsCount: findings.length,
    bySeverity,
    byCategory,
    scoredFindings,
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
}