/**
 * Extract layer: isolated Playwright instance per scan.
 * Deterministic capture only — no AI.
 */

import { chromium, type Browser, type Page, type Response } from 'playwright'
import { v4 as uuidv4 } from 'uuid'
import type {
  AssetInventory,
  CapturedHttpExchange,
  Cookie,
  DomFormField,
  Endpoint,
  ExternalScriptSource,
  ScanRequest,
} from '../core/types'
import { resolveDnsRecords } from './dns-probe'
import { scanTcpPorts } from './port-probe'
import { fingerprintTechnologies } from './technology-fingerprint'

function normalizeHeaders(headers: Record<string, string>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(headers)) {
    out[k.toLowerCase()] = v
  }
  return out
}

function determineEndpointType(resourceType: string): Endpoint['type'] {
  const typeMap: Record<string, Endpoint['type']> = {
    xhr: 'api',
    fetch: 'api',
    websocket: 'websocket',
    document: 'static',
    stylesheet: 'static',
    script: 'static',
    image: 'static',
    font: 'static',
    media: 'static',
  }
  return typeMap[resourceType] ?? 'static'
}

async function extractDomArtifacts(page: Page): Promise<{
  domForms: DomFormField[]
  externalScripts: ExternalScriptSource[]
}> {
  return page.evaluate(() => {
    const domForms: DomFormField[] = []
    for (const form of Array.from(document.querySelectorAll('form'))) {
      const fields: { name: string; type: string }[] = []
      for (const el of Array.from(form.querySelectorAll('input, textarea, select'))) {
        const name = (el as HTMLInputElement).name || (el as HTMLInputElement).id || '(unnamed)'
        fields.push({ name, type: (el as HTMLInputElement).type || el.tagName.toLowerCase() })
      }
      domForms.push({
        formAction: form.action || window.location.href,
        formMethod: (form.method || 'get').toUpperCase(),
        fields,
      })
    }
    const externalScripts: ExternalScriptSource[] = []
    for (const script of Array.from(document.querySelectorAll('script[src]'))) {
      externalScripts.push({
        src: (script as HTMLScriptElement).src,
        crossOrigin: script.getAttribute('crossorigin'),
      })
    }
    return { domForms, externalScripts }
  })
}

export class ScanWorker {
  /**
   * Each scan spins up an isolated browser instance and tears it down afterward.
   */
  async scan(request: ScanRequest): Promise<AssetInventory> {
    const scanId = uuidv4()
    const scanTime = new Date().toISOString()
    const target = new URL(request.targetUrl)
    const pageIsHttps = target.protocol === 'https:'

    const headers: Record<string, string> = {}
    const cookies: Cookie[] = []
    const endpoints: Endpoint[] = []
    const httpExchanges: CapturedHttpExchange[] = []
    const mixedContentViolations: string[] = []

    let browser: Browser | null = null

    try {
      browser = await chromium.launch({
        headless: true,
        args: ['--disable-blink-features=AutomationControlled', '--no-sandbox', '--disable-setuid-sandbox'],
      })

      const context = await browser.newContext({
        userAgent:
          'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        viewport: { width: 1920, height: 1080 },
        ignoreHTTPSErrors: true,
      })

      const page = await context.newPage()

      const onResponse = (response: Response) => {
        try {
          const req = response.request()
          const responseHeaders = normalizeHeaders(response.headers())
          const requestHeaders = normalizeHeaders(req.headers())

          httpExchanges.push({
            url: response.url(),
            method: req.method(),
            status: response.status(),
            resourceType: req.resourceType(),
            requestHeaders,
            responseHeaders,
          })

          endpoints.push({
            url: response.url(),
            method: req.method(),
            type: determineEndpointType(req.resourceType()),
            statusCode: response.status(),
            contentType: responseHeaders['content-type'],
          })

          if (req.resourceType() === 'document' && response.url().startsWith(target.origin)) {
            Object.assign(headers, responseHeaders)
          }

          if (
            pageIsHttps &&
            req.url().startsWith('http://') &&
            !req.url().startsWith('https://')
          ) {
            mixedContentViolations.push(req.url())
          }
        } catch {
          /* third-party frame failures must not abort scan */
        }
      }

      page.on('response', onResponse)

      page.on('pageerror', () => {
        /* ignore runtime script errors */
      })

      page.on('requestfailed', () => {
        /* tracking pixels / ad blockers — non-fatal */
      })

      try {
        await page.goto(request.targetUrl, { waitUntil: 'domcontentloaded', timeout: 45_000 })
        await page.waitForLoadState('networkidle', { timeout: 15_000 }).catch(() => {})
      } catch (err) {
        console.error(`Navigation partial for ${request.targetUrl}:`, err)
      }

      const browserCookies = await context.cookies()
      cookies.push(
        ...browserCookies.map((cookie) => ({
          name: cookie.name,
          domain: cookie.domain,
          path: cookie.path,
          httpOnly: cookie.httpOnly ?? false,
          secure: cookie.secure ?? false,
          sameSite: (cookie.sameSite as Cookie['sameSite']) ?? null,
          expires: cookie.expires ? new Date(cookie.expires * 1000).toISOString() : undefined,
        })),
      )

      let domForms: DomFormField[] = []
      let externalScripts: ExternalScriptSource[] = []
      try {
        const dom = await extractDomArtifacts(page)
        domForms = dom.domForms
        externalScripts = dom.externalScripts
      } catch {
        /* DOM extraction is best-effort */
      }

      const pageContent = await page.content().catch(() => '')
      const technologies = fingerprintTechnologies(pageContent, headers)

      const securityState = await page
        .evaluate(() => (window as unknown as { chrome?: { csi?: () => unknown } }).chrome)
        .catch(() => null)

      const tlsInfo = pageIsHttps
        ? {
            protocol: 'TLS (browser stack)',
            cipherSuite: securityState ? 'negotiated-in-browser' : 'unknown',
          }
        : undefined

      const dnsRecords = await resolveDnsRecords(target.hostname)
      const openPorts = await scanTcpPorts(target.hostname)

      return {
        targetUrl: page.url() || request.targetUrl,
        scanId,
        scanTime,
        orgType: request.orgType,
        technologies,
        headers,
        cookies,
        endpoints,
        tlsInfo,
        dnsRecords,
        openPorts,
        mixedContentViolations:
          mixedContentViolations.length > 0 ? [...new Set(mixedContentViolations)] : undefined,
        httpExchanges: httpExchanges.slice(0, 500),
        domForms,
        externalScripts,
        pageIsHttps,
      }
    } finally {
      if (browser) await browser.close().catch(() => {})
    }
  }
}

export async function createScanWorker(): Promise<ScanWorker> {
  return new ScanWorker()
}
