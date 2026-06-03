/**
 * Security Header Rules
 * Rules for missing or malformed security headers
 */

import { RuleDefinition, AssetInventory, Severity } from '../core/types';
import { createEvidence, createFinding } from './index';

export const securityHeaderRules: RuleDefinition[] = [
  {
    id: 'SEC-001',
    title: 'Missing HTTP Strict Transport Security (HSTS) Header',
    description: 'The HTTP Strict Transport Security (HSTS) header is not present, which allows man-in-the-middle attacks on HTTPS connections.',
    category: 'headers',
    severity: 'HIGH',
    cweId: 'CWE-319',
    check: (inventory: AssetInventory) => {
      const hstsHeader = inventory.headers['strict-transport-security'];
      
      if (!hstsHeader) {
        return createFinding(
          securityHeaderRules[0],
          createEvidence(
            'Response Headers',
            'strict-transport-security header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the Strict-Transport-Security header to your server configuration',
            'Recommended value: Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'Ensure your site is fully accessible over HTTPS before enabling HSTS'
          ]
        );
      }

      // Check if HSTS is properly configured
      if (!hstsHeader.includes('max-age=') || parseInt(hstsHeader.match(/max-age=(\d+)/)?.[1] || '0') < 31536000) {
        return createFinding(
          securityHeaderRules[0],
          createEvidence(
            'Response Headers -> Strict-Transport-Security',
            hstsHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Increase the max-age value to at least 31536000 (1 year)',
            'Consider adding includeSubDomains directive',
            'Recommended value: Strict-Transport-Security: max-age=31536000; includeSubDomains'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-002',
    title: 'Missing Content-Security-Policy (CSP) Header',
    description: 'The Content-Security-Policy header is not present, which increases the risk of cross-site scripting (XSS) attacks.',
    category: 'headers',
    severity: 'HIGH',
    cweId: 'CWE-693',
    check: (inventory: AssetInventory) => {
      const cspHeader = inventory.headers['content-security-policy'];
      
      if (!cspHeader) {
        return createFinding(
          securityHeaderRules[1],
          createEvidence(
            'Response Headers',
            'content-security-policy header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Implement a Content-Security-Policy header',
            'Start with a report-only mode to test: Content-Security-Policy-Report-Only: default-src \'self\'',
            'Gradually tighten the policy based on your application needs',
            'Example: Content-Security-Policy: default-src \'self\'; script-src \'self\' https://cdn.example.com'
          ]
        );
      }

      // Check for unsafe directives
      if (cspHeader.includes('unsafe-inline') || cspHeader.includes('unsafe-eval')) {
        return createFinding(
          securityHeaderRules[1],
          createEvidence(
            'Response Headers -> Content-Security-Policy',
            cspHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Remove unsafe-inline and unsafe-eval directives from CSP',
            'Use nonce or hash-based CSP instead',
            'Refactor JavaScript to avoid inline scripts and eval() usage'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-003',
    title: 'Missing X-Frame-Options Header',
    description: 'The X-Frame-Options header is not present, which allows the site to be framed and potentially vulnerable to clickjacking attacks.',
    category: 'headers',
    severity: 'MEDIUM',
    cweId: 'CWE-1021',
    check: (inventory: AssetInventory) => {
      const xFrameHeader = inventory.headers['x-frame-options'];
      
      if (!xFrameHeader) {
        return createFinding(
          securityHeaderRules[2],
          createEvidence(
            'Response Headers',
            'x-frame-options header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the X-Frame-Options header to prevent clickjacking',
            'Recommended value: X-Frame-Options: DENY or SAMEORIGIN',
            'Alternatively, use Content-Security-Policy with frame-ancestors directive'
          ]
        );
      }

      if (xFrameHeader !== 'DENY' && xFrameHeader !== 'SAMEORIGIN') {
        return createFinding(
          securityHeaderRules[2],
          createEvidence(
            'Response Headers -> X-Frame-Options',
            xFrameHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Change X-Frame-Options to DENY or SAMEORIGIN',
            'ALLOW-FROM is deprecated and should not be used'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-004',
    title: 'Missing X-Content-Type-Options Header',
    description: 'The X-Content-Type-Options header is not present, which can lead to MIME-sniffing vulnerabilities.',
    category: 'headers',
    severity: 'LOW',
    cweId: 'CWE-693',
    check: (inventory: AssetInventory) => {
      const xContentTypeHeader = inventory.headers['x-content-type-options'];
      
      if (!xContentTypeHeader) {
        return createFinding(
          securityHeaderRules[3],
          createEvidence(
            'Response Headers',
            'x-content-type-options header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the X-Content-Type-Options header',
            'Recommended value: X-Content-Type-Options: nosniff'
          ]
        );
      }

      if (xContentTypeHeader !== 'nosniff') {
        return createFinding(
          securityHeaderRules[3],
          createEvidence(
            'Response Headers -> X-Content-Type-Options',
            xContentTypeHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Change X-Content-Type-Options to nosniff'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-005',
    title: 'Missing X-XSS-Protection Header',
    description: 'The X-XSS-Protection header is not present, which disables the browser\'s built-in XSS filter.',
    category: 'headers',
    severity: 'LOW',
    check: (inventory: AssetInventory) => {
      const xXssHeader = inventory.headers['x-xss-protection'];
      
      if (!xXssHeader) {
        return createFinding(
          securityHeaderRules[4],
          createEvidence(
            'Response Headers',
            'x-xss-protection header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the X-XSS-Protection header as a defense-in-depth measure',
            'Recommended value: X-XSS-Protection: 1; mode=block',
            'Note: Modern browsers with CSP may not need this, but it provides legacy protection'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-006',
    title: 'Missing Referrer-Policy Header',
    description: 'The Referrer-Policy header is not present, which may leak sensitive information in the Referer header.',
    category: 'headers',
    severity: 'LOW',
    check: (inventory: AssetInventory) => {
      const referrerHeader = inventory.headers['referrer-policy'];
      
      if (!referrerHeader) {
        return createFinding(
          securityHeaderRules[5],
          createEvidence(
            'Response Headers',
            'referrer-policy header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the Referrer-Policy header to control referrer information',
            'Recommended value: Referrer-Policy: strict-origin-when-cross-origin',
            'For sensitive pages, use: Referrer-Policy: no-referrer'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'SEC-007',
    title: 'Missing Permissions-Policy Header',
    description: 'The Permissions-Policy (formerly Feature-Policy) header is not present, which may allow unwanted browser features.',
    category: 'headers',
    severity: 'LOW',
    check: (inventory: AssetInventory) => {
      const permissionsHeader = inventory.headers['permissions-policy'];
      
      if (!permissionsHeader) {
        return createFinding(
          securityHeaderRules[6],
          createEvidence(
            'Response Headers',
            'permissions-policy header is missing from response headers',
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Add the Permissions-Policy header to control browser features',
            'Example: Permissions-Policy: geolocation=(), camera=(), microphone=()',
            'Disable features that your application does not need'
          ]
        );
      }

      return null;
    }
  }
];
