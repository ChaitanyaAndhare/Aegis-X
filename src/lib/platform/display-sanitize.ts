/** Remove transport protocol references from user-visible copy. */

const STRIP_PATTERNS = [
  /\bhttps?:\/\//gi,
  /\bHTTP\s*\(cleartext\)\b/gi,
  /\bcleartext\s+HTTP\b/gi,
  /\bHTTPS\b/g,
  /\bHTTP\b/g,
  /\bHSTS\b/g,
  /strict-transport-security/gi,
]

const REPLACEMENTS: [RegExp, string][] = [
  [/\bCleartext HTTP\b/gi, 'Transport encryption not enforced'],
  [/\bHTTP only\b/gi, 'Transport encryption not enforced'],
  [/\bWeak transport \(observed\)\b/gi, 'Transport controls insufficient'],
  [/\bHTTPS with HSTS\b/gi, 'Transport hardening observed'],
  [/\bHTTPS without confirmed HSTS\b/gi, 'Transport partially hardened'],
]

export function displayTargetLabel(url?: string, title?: string): string {
  if (title && title !== 'Security assessment' && title !== 'Security Scan') return title
  if (!url) return 'Assessment target'
  try {
    const u = new URL(url)
    return u.hostname + (u.pathname !== '/' ? u.pathname.replace(/\/$/, '') : '')
  } catch {
    return url.replace(/^https?:\/\//i, '').split('/')[0] ?? url
  }
}

export function sanitizeForDisplay(text: string): string {
  let out = text
  for (const re of STRIP_PATTERNS) {
    out = out.replace(re, '')
  }
  for (const [re, rep] of REPLACEMENTS) {
    out = out.replace(re, rep)
  }
  return out.replace(/\s{2,}/g, ' ').trim()
}
