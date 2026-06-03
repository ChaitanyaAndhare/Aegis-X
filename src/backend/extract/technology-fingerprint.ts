import type { Technology } from '../core/types'

export function fingerprintTechnologies(
  html: string,
  headers: Record<string, string>,
): Technology[] {
  const technologies: Technology[] = []
  const serverHeader = headers['server'] ?? headers['Server'] ?? ''

  if (/nginx/i.test(serverHeader)) {
    technologies.push({
      name: 'Nginx',
      version: extractVersion(serverHeader),
      category: 'Web Server',
      confidence: 0.9,
    })
  }
  if (/apache/i.test(serverHeader)) {
    technologies.push({
      name: 'Apache',
      version: extractVersion(serverHeader),
      category: 'Web Server',
      confidence: 0.9,
    })
  }
  if (/cloudflare/i.test(serverHeader)) {
    technologies.push({ name: 'Cloudflare', version: '', category: 'CDN', confidence: 0.95 })
  }

  const poweredBy = headers['x-powered-by'] ?? ''
  if (/express/i.test(poweredBy)) {
    technologies.push({
      name: 'Express',
      version: extractVersion(poweredBy),
      category: 'Framework',
      confidence: 0.85,
    })
  }
  if (/php/i.test(poweredBy)) {
    technologies.push({
      name: 'PHP',
      version: extractVersion(poweredBy),
      category: 'Language',
      confidence: 0.9,
    })
  }

  const htmlSignals: [RegExp, Technology][] = [
    [/react|__NEXT_DATA__|data-reactroot/i, { name: 'React', version: '', category: 'JavaScript Framework', confidence: 0.75 }],
    [/vue\.js|data-v-/i, { name: 'Vue.js', version: '', category: 'JavaScript Framework', confidence: 0.75 }],
    [/angular|ng-app/i, { name: 'Angular', version: '', category: 'JavaScript Framework', confidence: 0.75 }],
    [/jquery/i, { name: 'jQuery', version: '', category: 'JavaScript Library', confidence: 0.8 }],
    [/bootstrap/i, { name: 'Bootstrap', version: '', category: 'CSS Framework', confidence: 0.8 }],
    [/tailwind/i, { name: 'Tailwind CSS', version: '', category: 'CSS Framework', confidence: 0.8 }],
    [/js\.stripe\.com|stripe\.com\/v3/i, { name: 'Stripe', version: '', category: 'Payment', confidence: 0.9 }],
    [/amazonaws\.com|aws-sdk/i, { name: 'AWS', version: '', category: 'Cloud', confidence: 0.7 }],
  ]

  for (const [pattern, tech] of htmlSignals) {
    if (pattern.test(html)) technologies.push(tech)
  }

  const cfRay = headers['cf-ray']
  if (cfRay && !technologies.some((t) => t.name === 'Cloudflare')) {
    technologies.push({ name: 'Cloudflare', version: '', category: 'CDN', confidence: 0.95 })
  }

  return technologies
}

function extractVersion(header: string): string {
  const versionMatch = header.match(/\/(\d+[\d.]*)/)
  return versionMatch ? versionMatch[1] : ''
}
