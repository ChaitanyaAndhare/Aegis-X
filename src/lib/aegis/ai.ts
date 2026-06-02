import { createOpenRouter } from '@openrouter/ai-sdk-provider'
import { generateObject, generateText } from 'ai'
import type { z } from 'zod'
import { AegisError } from './errors'

const EMBED_DIM = 1536

const MODEL_CHAIN = [
  'google/gemma-2-9b-it:free',
  'meta-llama/llama-3.3-70b-instruct:free',
  'deepseek/deepseek-chat:free',
  'openrouter/auto',
]

let keyLogged = false

export function logOpenRouterKeyStatus() {
  if (keyLogged) return
  keyLogged = true
  const loaded = Boolean(process.env.OPENROUTER_API_KEY?.trim())
  console.log(`[AEGIS] OpenRouter key loaded: ${loaded ? 'YES' : 'NO'}`)
  if (loaded) console.log(`[AEGIS] Model chain: ${MODEL_CHAIN.join(' → ')}`)
}

export function hasOpenRouterKey(): boolean {
  return Boolean(process.env.OPENROUTER_API_KEY?.trim())
}

function getProvider() {
  const apiKey = process.env.OPENROUTER_API_KEY?.trim()
  if (!apiKey) {
    throw new AegisError('MISSING_API_KEY', 'OpenRouter API key is missing. Add OPENROUTER_API_KEY to your .env file.')
  }
  return createOpenRouter({ apiKey })
}

export function getModel() {
  return hasOpenRouterKey() ? MODEL_CHAIN[0]! : 'none'
}

export function getEmbedModel() {
  return 'embeddings-disabled'
}

export async function embedText(_text: string): Promise<number[]> {
  return new Array(EMBED_DIM).fill(0)
}

async function withModelChain<T>(fn: (modelId: string) => Promise<T>): Promise<T> {
  const errors: string[] = []
  for (const modelId of MODEL_CHAIN) {
    try {
      return await fn(modelId)
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err)
      errors.push(`${modelId}: ${msg.slice(0, 120)}`)
      console.error(`[AEGIS] Model failed: ${modelId} — ${msg.slice(0, 120)}`)
      if (msg.toLowerCase().includes('rate limit') || msg.includes('429')) {
        throw new AegisError('RATE_LIMIT', 'OpenRouter rate limit reached. Wait a minute and try again.')
      }
    }
  }
  throw new AegisError('MODEL_UNAVAILABLE', `All models failed: ${errors.join(' | ')}`)
}

export async function structuredCall<T extends z.ZodType>(
  schema: T,
  system: string,
  prompt: string,
): Promise<{ object: z.infer<T>; tokens: number }> {
  return withModelChain(async (modelId) => {
    const openrouter = getProvider()
    const result = await generateObject({
      model: openrouter(modelId),
      schema,
      system: `${system}\n\nRespond with valid JSON matching the schema. No markdown.`,
      prompt,
      temperature: 0.2,
      maxRetries: 0,
      maxOutputTokens: 8192,
    })
    console.log(`[AEGIS] Model OK: ${modelId}`)
    return {
      object: result.object as z.infer<T>,
      tokens: result.usage?.totalTokens ?? 0,
    }
  })
}

export async function textCall(
  system: string,
  messages: { role: 'user' | 'assistant'; content: string }[],
): Promise<{ text: string; tokens: number }> {
  return withModelChain(async (modelId) => {
    const openrouter = getProvider()
    const result = await generateText({
      model: openrouter(modelId),
      system,
      messages,
      temperature: 0.35,
      maxOutputTokens: 1024,
    })
    console.log(`[AEGIS] Chat OK: ${modelId}`)
    return {
      text: result.text.trim(),
      tokens: result.usage?.totalTokens ?? 0,
    }
  })
}
