import { z } from 'zod'
import { structuredCall } from '../ai'
import { EXPERT_PERSONA, RECON_DEPTH } from '../expert-prompts'

export const ReconSchema = z.object({
  technologies: z.array(z.string()),
  attackSurface: z.array(z.string()),
  findings: z.array(
    z.object({
      signal: z.string(),
      detail: z.string(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).optional(),
      category: z.string().optional(),
    }),
  ),
  authModel: z.string().optional(),
  trustBoundaries: z.array(z.string()).default([]),
  exposureZones: z
    .array(
      z.object({
        zone: z.string(),
        assets: z.array(z.string()),
        risk: z.string(),
      }),
    )
    .default([]),
  infrastructureSignals: z.array(z.string()).default([]),
  dataFlowNotes: z.string().optional(),
})

export async function runRecon(input: {
  title: string
  targetUrl?: string
  appDescription?: string
  apiSpec?: string
  ctfDescription?: string
  pageSnippet?: string
  headersSummary?: string
}) {
  const prompt = `${RECON_DEPTH}

## Target
Title: ${input.title}
URL: ${input.targetUrl ?? 'N/A'}
Application context: ${input.appDescription ?? 'N/A'}
API specification: ${input.apiSpec ?? 'N/A'}
CTF / challenge: ${input.ctfDescription ?? 'N/A'}
${input.headersSummary ? `\n## HTTP / Security headers (observed)\n${input.headersSummary}` : ''}
${input.pageSnippet ? `\n## Page / response excerpt\n${input.pageSnippet.slice(0, 3500)}` : ''}

Deliver exhaustive recon: technologies, attack surface entries, categorized findings with severity, auth model narrative, trust boundaries, exposure zones, infrastructure signals, and data-flow notes for downstream risk modeling.`

  return structuredCall(
    ReconSchema,
    `${EXPERT_PERSONA}\n\nYou are AEGIS Recon — elite attack-surface mapping and security signal extraction. One structured JSON response only.`,
    prompt,
  )
}
