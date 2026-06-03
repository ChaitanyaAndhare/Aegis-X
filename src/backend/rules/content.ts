/**
 * Content Security Rules
 * Rules for mixed content and other content-related issues
 */

import { RuleDefinition, AssetInventory, Severity } from '../core/types';
import { createEvidence, createFinding } from './index';

export const contentRules: RuleDefinition[] = [
  {
    id: 'CONTENT-001',
    title: 'Mixed Content Detected',
    description: 'HTTPS page is loading HTTP resources, which creates security vulnerabilities and browser warnings.',
    category: 'content',
    severity: 'MEDIUM',
    cweId: 'CWE-311',
    check: (inventory: AssetInventory) => {
      if (inventory.mixedContentViolations && inventory.mixedContentViolations.length > 0) {
        const violations = inventory.mixedContentViolations.slice(0, 5).join(', ');
        return createFinding(
          contentRules[0],
          createEvidence(
            'Mixed Content Resources',
            `HTTP resources loaded on HTTPS page: ${violations}${inventory.mixedContentViolations.length > 5 ? '...' : ''}`,
            `Open browser DevTools Network tab on ${inventory.targetUrl}`
          ),
          [
            'Replace all HTTP resources with HTTPS equivalents',
            'Use protocol-relative URLs (//) or absolute HTTPS URLs',
            'Update all script, style, image, and iframe references',
            'Use a CSP upgrade-insecure-requests directive as a temporary fix'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'CONTENT-002',
    title: 'Insecure Form Action',
    description: 'Form action points to HTTP URL, which will submit sensitive data over an unencrypted connection.',
    category: 'content',
    severity: 'HIGH',
    cweId: 'CWE-319',
    check: (inventory: AssetInventory) => {
      // This would require DOM analysis - for now, check if target is HTTP
      if (inventory.targetUrl.startsWith('http://')) {
        return createFinding(
          contentRules[1],
          createEvidence(
            'Target URL Protocol',
            `Target URL uses HTTP instead of HTTPS: ${inventory.targetUrl}`,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Migrate the site to HTTPS',
            'Obtain an SSL/TLS certificate from a trusted CA',
            'Configure your server to redirect HTTP to HTTPS',
            'Update all internal links to use HTTPS'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'CONTENT-003',
    title: 'External JavaScript from Untrusted Domain',
    description: 'JavaScript is loaded from an external domain that may not be trusted, increasing supply chain attack risk.',
    category: 'content',
    severity: 'MEDIUM',
    cweId: 'CWE-829',
    check: (inventory: AssetInventory) => {
      const jsEndpoints = inventory.endpoints.filter(ep => 
        ep.type === 'static' && ep.url.match(/\.(js)$/i)
      );
      
      const externalJs = jsEndpoints.filter(ep => {
        const url = new URL(ep.url);
        const targetUrl = new URL(inventory.targetUrl);
        return url.hostname !== targetUrl.hostname;
      });
      
      if (externalJs.length > 0) {
        const domains = [...new Set(externalJs.map(ep => new URL(ep.url).hostname))].join(', ');
        return createFinding(
          contentRules[2],
          createEvidence(
            'External JavaScript Domains',
            `JavaScript loaded from external domains: ${domains}`,
            `Open browser DevTools Sources tab on ${inventory.targetUrl}`
          ),
          [
            'Audit all external JavaScript dependencies',
            'Host critical JavaScript libraries on your own domain',
            'Use Subresource Integrity (SRI) for external scripts',
            'Consider using a Content Security Policy to restrict script sources'
          ]
        );
      }

      return null;
    }
  }
];
