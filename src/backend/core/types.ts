/**
 * Core Data Models for AEGIS-X Enterprise ASM Platform
 * Pure deterministic types - no AI in backend
 */

export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type OrgType = 'Fintech' | 'Healthcare' | 'SaaS' | 'Startup' | 'Ecommerce' | 'Government';

export interface SecurityEvidence {
  timestamp: string;
  location: string; // e.g., "Response Headers -> Content-Security-Policy" or "DOM -> Form[action]"
  rawObserved: string; // The literal unedited text/byte snippet proving the issue
  reproduciblePayload?: string; // Vector to verify the finding manually
}

export interface SecurityFinding {
  id: string;
  ruleId: string;
  title: string;
  description: string;
  baseSeverity: Severity;
  contextualSeverity: Severity;
  evidence: SecurityEvidence;
  remediationSteps: string[];
  cweId?: string;
  cvssScore?: number;
}

export interface Technology {
  name: string;
  version: string;
  category: string;
  confidence: number; // 0-1
}

export interface Cookie {
  name: string;
  domain: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'Strict' | 'Lax' | 'None' | null;
  value?: string;
  expires?: string;
}

export interface Endpoint {
  url: string;
  method: string;
  type: 'api' | 'static' | 'form' | 'websocket';
  statusCode?: number;
  contentType?: string;
}

export interface CapturedHttpExchange {
  url: string;
  method: string;
  status: number;
  resourceType: string;
  requestHeaders: Record<string, string>;
  responseHeaders: Record<string, string>;
}

export interface DomFormField {
  formAction: string;
  formMethod: string;
  fields: { name: string; type: string }[];
}

export interface ExternalScriptSource {
  src: string;
  crossOrigin: string | null;
}

export interface AssetInventory {
  targetUrl: string;
  scanId: string;
  scanTime: string;
  orgType: OrgType;
  technologies: Technology[];
  headers: Record<string, string>;
  cookies: Cookie[];
  endpoints: Endpoint[];
  tlsInfo?: {
    protocol: string;
    cipherSuite: string;
    certificateIssuer?: string;
    certificateValidUntil?: string;
  };
  dnsRecords?: {
    A?: string[];
    AAAA?: string[];
    MX?: string[];
    TXT?: string[];
    CNAME?: string[];
  };
  openPorts?: number[];
  mixedContentViolations?: string[];
  httpExchanges?: CapturedHttpExchange[];
  domForms?: DomFormField[];
  externalScripts?: ExternalScriptSource[];
  pageIsHttps?: boolean;
}

export interface ScanDelta {
  newFindings: SecurityFinding[];
  resolvedFindings: SecurityFinding[];
  stableFindings: SecurityFinding[];
  newAssets: AssetInventory[];
  removedAssets: AssetInventory[];
  timestamp: string;
}

export interface SecurityDebtScore {
  totalScore: number; // 0-100
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  trend: 'improving' | 'degrading' | 'stable';
  complianceFlags: {
    pciDss: boolean;
    soc2: boolean;
    gdpr: boolean;
    hipaa: boolean;
  };
}

export interface ScanRequest {
  targetUrl: string;
  orgType: OrgType;
  scanDepth: 'basic' | 'standard' | 'deep';
  includeSubdomains?: boolean;
  maxPages?: number;
}

export interface ScanResult {
  scanId: string;
  request: ScanRequest;
  assetInventory: AssetInventory;
  findings: SecurityFinding[];
  securityDebt: SecurityDebtScore;
  delta?: ScanDelta;
  timestamp: string;
  duration: number; // seconds
  status: 'completed' | 'failed' | 'partial';
  error?: string;
}

export interface RuleDefinition {
  id: string;
  title: string;
  description: string;
  category: 'headers' | 'cookies' | 'content' | 'tls' | 'dns' | 'info-leakage';
  severity: Severity;
  check: (inventory: AssetInventory) => SecurityFinding | null;
  cweId?: string;
}
