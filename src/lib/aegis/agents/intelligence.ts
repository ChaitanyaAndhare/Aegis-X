import { z } from 'zod'
import { structuredCall } from '../ai'
import { EXPERT_PERSONA, INTEL_DEPTH } from '../expert-prompts'

export const IntelligenceSchema = z.object({
  executiveV2: z.object({
    overallPosture: z.string(),
    topRisk: z.string(),
    businessImpact: z.string(),
    priorityFix: z.string(),
    estimatedRiskReduction: z.string(),
    recommendedTimeline: z.string(),
  }),
  summary: z.string(),
  recommendations: z.array(z.string()),
  nextSteps: z.array(z.string()),
  intelligence: z.object({
    observedTechnologies: z.array(z.string()),
    commonRisks: z.array(z.string()),
    likelyMaturity: z.string(),
    securityPosture: z.string(),
  }),
  securityDNA: z.object({
    architecture: z.string(),
    exposure: z.string(),
    maturity: z.string(),
    attackSurface: z.string(),
    hardening: z.string(),
  }),
  attackerPerspective: z.object({
    immediateObservations: z.array(z.string()),
    mostAttractiveTarget: z.string(),
    probableObjective: z.string(),
    probableRoute: z.string(),
    narrative: z.string(),
  }),
  expertAssessment: z.object({
    methodology: z.string(),
    assumptions: z.array(z.string()),
    blindSpots: z.array(z.string()),
    redTeamVerdict: z.string(),
  }),
  defensePriorities: z.array(
    z.object({
      rank: z.number(),
      action: z.string(),
      rationale: z.string(),
      effort: z.enum(['S', 'M', 'L']),
    }),
  ),
})

export async function runIntelligenceSynthesis(input: {
  context: string
  reconJson: string
  riskJson: string
  threatJson: string
  score: number
  grade: string
}) {
  const prompt = `${INTEL_DEPTH}

Context:
${input.context}

Score: ${input.score} (${input.grade})

Recon: ${input.reconJson}
Risk: ${input.riskJson}
Threats: ${input.threatJson}`

  return structuredCall(
    IntelligenceSchema,
    `${EXPERT_PERSONA}\n\nYou are AEGIS Intelligence — executive and remediation synthesis.`,
    prompt,
  )
}
