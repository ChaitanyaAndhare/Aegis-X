/**
 * Cookie Security Rules
 * Rules for insecure cookie configurations
 */

import { RuleDefinition, AssetInventory, Severity } from '../core/types';
import { createEvidence, createFinding } from './index';

export const cookieRules: RuleDefinition[] = [
  {
    id: 'COOKIE-001',
    title: 'Cookie Missing Secure Flag',
    description: 'One or more cookies are missing the Secure flag, which allows them to be transmitted over unencrypted HTTP connections.',
    category: 'cookies',
    severity: 'HIGH',
    cweId: 'CWE-614',
    check: (inventory: AssetInventory) => {
      const insecureCookies = inventory.cookies.filter(cookie => !cookie.secure);
      
      if (insecureCookies.length > 0) {
        const cookieNames = insecureCookies.map(c => c.name).join(', ');
        return createFinding(
          cookieRules[0],
          createEvidence(
            'Response Cookies',
            `Cookies without Secure flag: ${cookieNames}`,
            `curl -I ${inventory.targetUrl} | grep -i set-cookie`
          ),
          [
            'Set the Secure flag on all cookies',
            'For session cookies: Set-Cookie: sessionid=xxx; Secure; HttpOnly; SameSite=Strict',
            'Ensure your site is fully HTTPS before enabling Secure flag'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'COOKIE-002',
    title: 'Cookie Missing HttpOnly Flag',
    description: 'One or more cookies are missing the HttpOnly flag, which allows JavaScript to access them and increases XSS risk.',
    category: 'cookies',
    severity: 'MEDIUM',
    cweId: 'CWE-1004',
    check: (inventory: AssetInventory) => {
      const accessibleCookies = inventory.cookies.filter(cookie => !cookie.httpOnly);
      
      if (accessibleCookies.length > 0) {
        const cookieNames = accessibleCookies.map(c => c.name).join(', ');
        return createFinding(
          cookieRules[1],
          createEvidence(
            'Response Cookies',
            `Cookies without HttpOnly flag: ${cookieNames}`,
            `curl -I ${inventory.targetUrl} | grep -i set-cookie`
          ),
          [
            'Set the HttpOnly flag on all sensitive cookies',
            'For session cookies: Set-Cookie: sessionid=xxx; Secure; HttpOnly; SameSite=Strict',
            'This prevents JavaScript from accessing the cookie via document.cookie'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'COOKIE-003',
    title: 'Cookie Missing SameSite Attribute',
    description: 'One or more cookies are missing the SameSite attribute, which increases CSRF risk.',
    category: 'cookies',
    severity: 'MEDIUM',
    cweId: 'CWE-352',
    check: (inventory: AssetInventory) => {
      const cookiesWithoutSameSite = inventory.cookies.filter(cookie => !cookie.sameSite || cookie.sameSite === 'None');
      
      if (cookiesWithoutSameSite.length > 0) {
        const cookieNames = cookiesWithoutSameSite.map(c => c.name).join(', ');
        return createFinding(
          cookieRules[2],
          createEvidence(
            'Response Cookies',
            `Cookies without SameSite=Strict or SameSite=Lax: ${cookieNames}`,
            `curl -I ${inventory.targetUrl} | grep -i set-cookie`
          ),
          [
            'Set the SameSite attribute on all cookies',
            'For session cookies: SameSite=Strict',
            'For general cookies: SameSite=Lax',
            'Only use SameSite=None with Secure flag for cross-site cookies'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'COOKIE-004',
    title: 'Cookie with SameSite=None but Missing Secure Flag',
    description: 'A cookie has SameSite=None but is missing the Secure flag, which is invalid and will be rejected by modern browsers.',
    category: 'cookies',
    severity: 'HIGH',
    check: (inventory: AssetInventory) => {
      const invalidCookies = inventory.cookies.filter(cookie => cookie.sameSite === 'None' && !cookie.secure);
      
      if (invalidCookies.length > 0) {
        const cookieNames = invalidCookies.map(c => c.name).join(', ');
        return createFinding(
          cookieRules[3],
          createEvidence(
            'Response Cookies',
            `Cookies with SameSite=None but missing Secure flag: ${cookieNames}`,
            `curl -I ${inventory.targetUrl} | grep -i set-cookie`
          ),
          [
            'Add the Secure flag to cookies with SameSite=None',
            'Modern browsers require Secure flag when SameSite=None',
            'Correct configuration: Set-Cookie: cookie=value; SameSite=None; Secure'
          ]
        );
      }

      return null;
    }
  },

  {
    id: 'COOKIE-005',
    title: 'Cookie with Excessive Expiration Time',
    description: 'One or more cookies have expiration times far in the future, which increases the risk of long-term cookie theft.',
    category: 'cookies',
    severity: 'LOW',
    check: (inventory: AssetInventory) => {
      const now = new Date();
      const oneYearFromNow = new Date(now.getTime() + 365 * 24 * 60 * 60 * 1000);
      
      const longLivedCookies = inventory.cookies.filter(cookie => {
        if (!cookie.expires) return false;
        const expiresDate = new Date(cookie.expires);
        return expiresDate > oneYearFromNow;
      });
      
      if (longLivedCookies.length > 0) {
        const cookieNames = longLivedCookies.map(c => c.name).join(', ');
        return createFinding(
          cookieRules[4],
          createEvidence(
            'Response Cookies',
            `Cookies with expiration > 1 year: ${cookieNames}`,
            `curl -I ${inventory.targetUrl} | grep -i set-cookie`
          ),
          [
            'Reduce cookie expiration times to the minimum required',
            'For session cookies, use session cookies (no expiration)',
            'For persistent cookies, use expiration times appropriate to the use case'
          ]
        );
      }

      return null;
    }
  }
];
