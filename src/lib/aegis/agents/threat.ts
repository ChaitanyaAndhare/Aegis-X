import { z } from 'zod'
import { structuredCall } from '../ai'
import { EXPERT_PERSONA, THREAT_DEPTH } from '../expert-prompts'

const AttackSchema = z.object({
  name: z.string(),
  description: z.string(),
  chain: z.array(z.string()),
  confidence: z.number(),
  mitreTechniques: z.array(z.string()).default([]),
})

export const ThreatSchema = z.object({
  threats: z.array(
    z.object({
      name: z.string(),
      description: z.string(),
      severity: z.string(),
      strideCategory: z.string().optional(),
    }),
  ),
  attackChains: z.array(AttackSchema),
  businessImpact: z.array(z.string()),
  confidence: z.number(),
  mostLikely: AttackSchema,
  mostDangerous: AttackSchema,
  mostRealistic: AttackSchema,
  adversaryPersonas: z
    .array(
      z.object({
        name: z.string(),
        objective: z.string(),
        capability: z.string(),
      }),
    )
    .default([]),
  killChainPhases: z.array(z.object({ phase: z.string(), activity: z.string() })).default([]),
  strideSummary: z.string().optional(),
})

export async function runThreatModeling(input: { context: string; reconJson: string; riskJson: string }) {
  const prompt = `${THREAT_DEPTH}

## Context
${input.context}

## Recon
${input.reconJson}

## Risk analysis
${input.riskJson}

Identify threats with STRIDE categories, synthesize attack chains, business impact bullets, adversary personas, and kill-chain phases.
Define mostLikely, mostDangerous, mostRealistic with detailed step chains (4–7 steps each) and MITRE technique references where applicable.
Provide strideSummary: one paragraph tying threats to architecture.`

  return structuredCall(
    ThreatSchema,
    `${EXPERT_PERSONA}\n\nYou are AEGIS Threat Modeler — STRIDE, kill-chain, and adversary-driven threat synthesis.`,
    prompt,
  )
}
