import {
  SEVERITY_SCORES,
  CONFIDENCE_MULTIPLIERS,
  RISK_THRESHOLDS,
  calculateFindingScore,
  getRiskLevel,
} from "../patterns/index.js"

export function calculateProjectScore(findings) {
  if (!findings || findings.length === 0) {
    return {
      totalScore: 0,
      riskLevel: "LOW",
      findingsCount: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byCategory: {},
    }
  }

  let totalScore = 0
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 }
  const byCategory = {}
  const scoredFindings = []

  for (const finding of findings) {
    const score = calculateFindingScore(finding)
    totalScore += score

    bySeverity[finding.severity]++
    byCategory[finding.category] = (byCategory[finding.category] || 0) + 1

    scoredFindings.push({ ...finding, score })
  }

  const riskLevel = getRiskLevel(totalScore)

  return {
    totalScore: Math.round(totalScore * 10) / 10,
    riskLevel,
    findingsCount: findings.length,
    bySeverity,
    byCategory,
    scoredFindings,
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