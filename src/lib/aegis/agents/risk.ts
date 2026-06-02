import { z } from 'zod'
import { structuredCall } from '../ai'
import { EXPERT_PERSONA, RISK_DEPTH } from '../expert-prompts'

export const RiskSchema = z.object({
  vulnerabilities: z.array(
    z.object({
      id: z.string(),
      title: z.string(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']),
      description: z.string(),
      confidence: z.number().min(0).max(1),
      evidence: z.string(),
      observedSignal: z.string(),
      reasoning: z.string(),
      potentialImpact: z.string(),
      recommendedFix: z.string(),
      cwe: z.string().optional(),
      remediation: z.string().optional(),
      impact: z.number().min(0).max(10),
      likelihood: z.number().min(0).max(10),
      exploitability: z.number().min(0).max(10),
      businessCost: z.string(),
      priority: z.number().min(1).max(10),
      attackVector: z.string().optional(),
      mitreTactics: z.array(z.string()).default([]),
      prerequisites: z.array(z.string()).default([]),
      detectionDifficulty: z.enum(['low', 'medium', 'high']).optional(),
    }),
  ),
  attackPaths: z.array(z.object({ source: z.string(), target: z.string(), label: z.string() })),
  simulatedPaths: z.array(
    z.object({
      id: z.string(),
      name: z.string(),
      steps: z.array(z.string()),
      likelihood: z.number(),
      impact: z.number(),
      difficulty: z.number(),
      objective: z.string().optional(),
      mitreTechniques: z.array(z.string()).default([]),
    }),
  ),
  riskLevel: z.string(),
  riskNarrative: z.string().optional(),
})

export async function runRiskAnalysis(input: { context: string; reconJson: string }) {
  const prompt = `${RISK_DEPTH}

Context:
${input.context}

Recon:
${input.reconJson}

Return 4-8 findings. Each MUST have evidence + observedSignal from recon data.`

  return structuredCall(
    RiskSchema,
    `${EXPERT_PERSONA}\n\nYou are AEGIS Risk Analysis — evidence-based finding generation.`,
    prompt,
  )
}
