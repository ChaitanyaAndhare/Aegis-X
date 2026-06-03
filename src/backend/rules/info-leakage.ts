/**
 * Information Leakage Rules
 * Rules for exposed information leakage in headers and responses
 */

import { RuleDefinition, AssetInventory, Severity } from '../core/types';
import { createEvidence, createFinding } from './index';

export const infoLeakageRules: RuleDefinition[] = [
  {
    id: 'INFO-001',
    title: 'Server Header Exposes Version Information',
    description: 'The Server header exposes specific software version information, which aids attackers in targeting known vulnerabilities.',
    category: 'info-leakage',
    severity: 'LOW',
    cweId: 'CWE-200',
    check: (inventory: AssetInventory) => {
      const serverHeader = inventory.headers['server'];
      
      if (serverHeader && serverHeader.match(/\d+\.\d+/)) {
        return createFinding(
          infoLeakageRules[0],
          createEvidence(
            'Response Headers -> Server',
            serverHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Remove version information from the Server header',
            'Configure your web server to hide version numbers',
            'For Nginx: server_tokens off;',
            'For Apache: ServerTokens Prod and ServerSignature Off'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'INFO-002',
    title: 'X-Powered-By Header Exposes Technology',
    description: 'The X-Powered-By header exposes the underlying technology stack, which aids attackers in reconnaissance.',
    category: 'info-leakage',
    severity: 'LOW',
    cweId: 'CWE-200',
    check: (inventory: AssetInventory) => {
      const poweredByHeader = inventory.headers['x-powered-by'];
      
      if (poweredByHeader) {
        return createFinding(
          infoLeakageRules[1],
          createEvidence(
            'Response Headers -> X-Powered-By',
            poweredByHeader,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Remove the X-Powered-By header',
            'For Express: app.disable(\'x-powered-by\');',
            'For PHP: expose_php = Off in php.ini',
            'Configure your framework to disable this header'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'INFO-003',
    title: 'X-AspNet-Version Header Exposes Framework Version',
    description: 'The X-AspNet-Version header exposes the ASP.NET framework version, which aids attackers in targeting known vulnerabilities.',
    category: 'info-leakage',
    severity: 'LOW',
    cweId: 'CWE-200',
    check: (inventory: AssetInventory) => {
      const aspNetVersion = inventory.headers['x-aspnet-version'];
      
      if (aspNetVersion) {
        return createFinding(
          infoLeakageRules[2],
          createEvidence(
            'Response Headers -> X-AspNet-Version',
            aspNetVersion,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Remove the X-AspNet-Version header',
            'Add to web.config: <httpRuntime enableVersionHeader="false" />',
            'This header is unnecessary and provides no functional benefit'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'INFO-004',
    title: 'X-AspNetMvc-Version Header Exposes MVC Version',
    description: 'The X-AspNetMvc-Version header exposes the ASP.NET MVC version, which aids attackers in targeting known vulnerabilities.',
    category: 'info-leakage',
    severity: 'LOW',
    cweId: 'CWE-200',
    check: (inventory: AssetInventory) => {
      const aspNetMvcVersion = inventory.headers['x-aspnetmvc-version'];
      
      if (aspNetMvcVersion) {
        return createFinding(
          infoLeakageRules[3],
          createEvidence(
            'Response Headers -> X-AspNetMvc-Version',
            aspNetMvcVersion,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Remove the X-AspNetMvc-Version header',
            'Add to Application_Start: MvcHandler.DisableMvcResponseHeader = true;',
            'This header is unnecessary and provides no functional benefit'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'INFO-005',
    title: 'Debug Mode Enabled in Headers',
    description: 'Debug-related headers suggest the application is running in debug mode, which may expose sensitive information.',
    category: 'info-leakage',
    severity: 'MEDIUM',
    cweId: 'CWE-489',
    check: (inventory: AssetInventory) => {
      const debugHeaders = Object.keys(inventory.headers).filter(key => 
        key.toLowerCase().includes('debug') || 
        key.toLowerCase().includes('trace') ||
        key.toLowerCase().includes('dev')
      );
      
      if (debugHeaders.length > 0) {
        const headerInfo = debugHeaders.map(h => `${h}: ${inventory.headers[h]}`).join(', ');
        return createFinding(
          infoLeakageRules[4],
          createEvidence(
            'Response Headers',
            headerInfo,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Disable debug mode in production',
            'Remove debug-related headers from responses',
            'Ensure DEBUG=False in Django, NODE_ENV=production in Node.js, etc.',
            'Review your framework\'s production configuration'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'INFO-006',
    title: 'Cloudflare CDN Detected Without WAF Configuration',
    description: 'Cloudflare CDN is detected but WAF configuration status cannot be verified. Ensure WAF rules are properly configured.',
    category: 'info-leakage',
    severity: 'INFO',
    check: (inventory: AssetInventory) => {
      const cfRay = inventory.headers['cf-ray'];
      
      if (cfRay) {
        return createFinding(
          infoLeakageRules[5],
          createEvidence(
            'Response Headers -> CF-Ray',
            cfRay,
            `curl -I ${inventory.targetUrl}`
          ),
          [
            'Verify Cloudflare WAF rules are properly configured',
            'Review Cloudflare security level settings',
            'Ensure managed rulesets are enabled',
            'Consider implementing custom WAF rules for your application'
          ]
        );
      }

      return null;
    }
  }
];
