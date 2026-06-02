export type AegisErrorCode =
  | 'MISSING_API_KEY'
  | 'MODEL_UNAVAILABLE'
  | 'RATE_LIMIT'
  | 'INVALID_URL'
  | 'UNAUTHORIZED'
  | 'NETWORK_ERROR'
  | 'UNKNOWN'

export class AegisError extends Error {
  code: AegisErrorCode
  userMessage: string

  constructor(code: AegisErrorCode, userMessage: string, cause?: unknown) {
    super(userMessage)
    this.name = 'AegisError'
    this.code = code
    this.userMessage = userMessage
    if (cause instanceof Error) this.cause = cause
  }
}

export function mapToAegisError(err: unknown): AegisError {
  const msg = err instanceof Error ? err.message : String(err)
  const lower = msg.toLowerCase()

  if (lower.includes('openrouter_api_key') || lower.includes('missing api key')) {
    return new AegisError('MISSING_API_KEY', 'OpenRouter API key is missing. Add OPENROUTER_API_KEY to your .env file.')
  }
  if (lower.includes('rate limit') || lower.includes('429')) {
    return new AegisError('RATE_LIMIT', 'OpenRouter rate limit reached. Wait a moment and try again.')
  }
  if (lower.includes('invalid url') || lower.includes('failed to parse url')) {
    return new AegisError('INVALID_URL', 'The website URL is invalid or unreachable.')
  }
  if (lower.includes('fetch failed') || lower.includes('network') || lower.includes('econnrefused')) {
    return new AegisError('NETWORK_ERROR', 'Network error while contacting the target or OpenRouter.')
  }
  if (lower.includes('model') || lower.includes('503') || lower.includes('502')) {
    return new AegisError('MODEL_UNAVAILABLE', 'AI model unavailable. Retrying with fallback may help.')
  }
  return new AegisError('UNKNOWN', msg || 'An unexpected error occurred during the scan.')
}
