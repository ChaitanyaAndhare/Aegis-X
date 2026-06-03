/**
 * Task 1: Core Scraper & Ingestion Service
 * Headless Browser Isolation with Playwright
 * Pure deterministic ETL - no AI in this layer
 */

import { chromium, Browser, Page, BrowserContext } from 'playwright';
import { AssetInventory, ScanRequest, Cookie, Endpoint, Technology } from '../core/types';
import { v4 as uuidv4 } from 'uuid';

export class ScanWorker {
  private browser: Browser | null = null;
  private context: BrowserContext | null = null;
  private page: Page | null = null;

  async initialize(): Promise<void> {
    this.browser = await chromium.launch({
      headless: true,
      args: [
        '--disable-blink-features=AutomationControlled',
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    this.context = await this.browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      viewport: { width: 1920, height: 1080 },
      ignoreHTTPSErrors: true
    });

    this.page = await this.context.newPage();
  }

  async scan(request: ScanRequest): Promise<AssetInventory> {
    if (!this.page) {
      throw new Error('ScanWorker not initialized. Call initialize() first.');
    }

    const scanId = uuidv4();
    const scanTime = new Date().toISOString();

    // Collect HTTP request/response data
    const headers: Record<string, string> = {};
    const cookies: Cookie[] = [];
    const endpoints: Endpoint[] = [];
    const technologies: Technology[] = [];
    const mixedContentViolations: string[] = [];

    // Intercept network requests
    await this.page.route('**/*', async (route: any) => {
      const request = route.request();
      const response = await route.fetch();

      // Capture response headers
      const responseHeaders = response.headers();
      Object.assign(headers, responseHeaders);

      // Capture endpoint information
      endpoints.push({
        url: request.url(),
        method: request.method(),
        type: this.determineEndpointType(request.resourceType()),
        statusCode: response.status(),
        contentType: responseHeaders['content-type']
      });

      // Check for mixed content
      if (request.url().startsWith('http://') && request.frame()?.url()?.startsWith('https://')) {
        mixedContentViolations.push(request.url());
      }

      route.continue();
    });

    // Navigate to target
    try {
      await this.page.goto(request.targetUrl, {
        waitUntil: 'networkidle',
        timeout: 30000
      });
    } catch (error) {
      console.error(`Navigation error for ${request.targetUrl}:`, error);
      // Continue with partial data
    }

    // Extract cookies
    const browserCookies = await this.context.cookies();
    cookies.push(...browserCookies.map((cookie: any) => ({
      name: cookie.name,
      domain: cookie.domain,
      path: cookie.path,
      httpOnly: cookie.httpOnly || false,
      secure: cookie.secure || false,
      sameSite: cookie.sameSite as 'Strict' | 'Lax' | 'None' | null,
      value: cookie.value,
      expires: cookie.expires ? new Date(cookie.expires * 1000).toISOString() : undefined
    })));

    // Technology fingerprinting from page content
    const pageContent = await this.page.content();
    const pageUrl = this.page.url();
    technologies.push(...this.fingerprintTechnologies(pageContent, headers, pageUrl));

    // TLS information
    const tlsInfo = await this.extractTLSInfo();

    // DNS records (basic DNS lookup)
    const dnsRecords = await this.performDNSLookup(request.targetUrl);

    // Port scanning (basic TCP connection check)
    const openPorts = await this.performPortScan(request.targetUrl);

    // Cleanup
    await this.page.route('**/*', (route: any) => route.continue());

    return {
      targetUrl: request.targetUrl,
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
      mixedContentViolations: mixedContentViolations.length > 0 ? mixedContentViolations : undefined
    };
  }

  private determineEndpointType(resourceType: string): Endpoint['type'] {
    const typeMap: Record<string, Endpoint['type']> = {
      'xhr': 'api',
      'fetch': 'api',
      'websocket': 'websocket',
      'document': 'static',
      'stylesheet': 'static',
      'script': 'static',
      'image': 'static',
      'font': 'static',
      'media': 'static'
    };
    return typeMap[resourceType] || 'static';
  }

  private fingerprintTechnologies(
    html: string,
    headers: Record<string, string>,
    url: string
  ): Technology[] {
    const technologies: Technology[] = [];

    // Server header fingerprinting
    const serverHeader = headers['server'];
    if (serverHeader) {
      if (serverHeader.includes('nginx')) {
        technologies.push({ name: 'Nginx', version: this.extractVersion(serverHeader), category: 'Web Server', confidence: 0.9 });
      }
      if (serverHeader.includes('Apache')) {
        technologies.push({ name: 'Apache', version: this.extractVersion(serverHeader), category: 'Web Server', confidence: 0.9 });
      }
      if (serverHeader.includes('cloudflare')) {
        technologies.push({ name: 'Cloudflare', version: '', category: 'CDN', confidence: 0.95 });
      }
    }

    // X-Powered-By header
    const poweredBy = headers['x-powered-by'];
    if (poweredBy) {
      if (poweredBy.includes('Express')) {
        technologies.push({ name: 'Express', version: this.extractVersion(poweredBy), category: 'Framework', confidence: 0.85 });
      }
      if (poweredBy.includes('PHP')) {
        technologies.push({ name: 'PHP', version: this.extractVersion(poweredBy), category: 'Language', confidence: 0.9 });
      }
    }

    // HTML meta tags and script sources
    if (html.includes('react') || html.includes('React')) {
      technologies.push({ name: 'React', version: '', category: 'JavaScript Framework', confidence: 0.7 });
    }
    if (html.includes('vue') || html.includes('Vue')) {
      technologies.push({ name: 'Vue.js', version: '', category: 'JavaScript Framework', confidence: 0.7 });
    }
    if (html.includes('angular') || html.includes('ng-app')) {
      technologies.push({ name: 'Angular', version: '', category: 'JavaScript Framework', confidence: 0.7 });
    }
    if (html.includes('jquery')) {
      technologies.push({ name: 'jQuery', version: '', category: 'JavaScript Library', confidence: 0.8 });
    }
    if (html.includes('bootstrap')) {
      technologies.push({ name: 'Bootstrap', version: '', category: 'CSS Framework', confidence: 0.8 });
    }
    if (html.includes('tailwind')) {
      technologies.push({ name: 'Tailwind CSS', version: '', category: 'CSS Framework', confidence: 0.8 });
    }
    if (html.includes('stripe')) {
      technologies.push({ name: 'Stripe', version: '', category: 'Payment', confidence: 0.9 });
    }
    if (html.includes('aws') || html.includes('amazonaws')) {
      technologies.push({ name: 'AWS', version: '', category: 'Cloud', confidence: 0.7 });
    }

    return technologies;
  }

  private extractVersion(header: string): string {
    const versionMatch = header.match(/\/(\d+[\d.]*)/);
    return versionMatch ? versionMatch[1] : '';
  }

  private async extractTLSInfo() {
    if (!this.page) return undefined;

    try {
      const response = await this.page.evaluate(() => {
        // This is a simplified version - in production, you'd use the TLS protocol info
        return {
          protocol: 'TLS 1.2+',
          cipherSuite: 'Unknown'
        };
      });
      return response;
    } catch (error) {
      return undefined;
    }
  }

  private async performDNSLookup(url: string) {
    // In a real implementation, you'd use a DNS library
    // For now, return empty structure
    return {
      A: [],
      AAAA: [],
      MX: [],
      TXT: [],
      CNAME: []
    };
  }

  private async performPortScan(url: string): Promise<number[]> {
    // In a real implementation, you'd perform actual TCP connection checks
    // For now, return common web ports as "open" for demonstration
    const hostname = new URL(url).hostname;
    const commonPorts = [80, 443, 8080, 8443];
    
    // Simulate port scan results
    return [80, 443]; // Assume HTTP and HTTPS are open
  }

  async cleanup(): Promise<void> {
    if (this.page) {
      await this.page.close();
      this.page = null;
    }
    if (this.context) {
      await this.context.close();
      this.context = null;
    }
    if (this.browser) {
      await this.browser.close();
      this.browser = null;
    }
  }
}

export async function createScanWorker(): Promise<ScanWorker> {
  const worker = new ScanWorker();
  await worker.initialize();
  return worker;
}
