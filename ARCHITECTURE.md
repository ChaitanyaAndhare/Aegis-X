# AEGIS-X Enterprise Architecture

## Overview

AEGIS-X has been completely rebuilt as an enterprise-grade Attack Surface Management (ASM) platform with a **deterministic Security ETL pipeline**. The backend operates with **ZERO AI** in the ingestion or evaluation loop. AI is strictly confined to the presentation layer as an asynchronous "Copilot" for generating human-readable remediation summaries.

## Core Philosophy

**Engineering Determinism**: Every security finding is backed by cryptographic-like evidence objects containing:
- Exact timestamps
- Literal raw matching lines
- Payload snippets
- URI contexts

No generic explanations. No AI hallucinations. Pure, verifiable evidence.

## Architecture Blueprint

### 1. EXTRACT LAYER (Ingestion)

**Location**: `src/backend/extract/`

**Component**: `ScanWorker` (Playwright-based)

**Responsibilities**:
- Headless Browser Isolation: Spin up isolated Playwright instances per scan
- Network & DOM Interception: Capture every HTTP request/response frame
- TLS Handshake Details: Full protocol and cipher suite information
- Cookie Extraction: Complete cookie attributes (Secure, HttpOnly, SameSite)
- Session Storage Analysis: Schema extraction
- Hidden Form Field Detection
- External Script Source Tracking
- Passive DNS Discovery: A, AAAA, MX, TXT, CNAME records
- Port Discovery: TCP socket connection checks on standard web ports (80, 443, 8080, 8443)

**Error Handling**: Graceful degradation - third-party tracking script failures don't fail the entire scan.

### 2. TRANSFORM LAYER (Normalization & Heuristics)

**Location**: `src/backend/transform/`

**Components**:
- `risk-profiler.ts`: Context-aware severity adjustment
- `security-debt-calculator.ts`: Dynamic risk scoring

**Responsibilities**:

#### Technology Fingerprinting
- Structural regex matching against:
  - Raw text headers
  - HTML bodies
  - Global window object properties
- Wappalyzer-grade matching for:
  - Cloudflare, React, AWS, Stripe
  - Nginx, Apache, Express
  - PHP, Node.js, Python

#### Deterministic Security Rules Engine
**Location**: `src/backend/rules/`

File-based rules database (`/rules/*.ts`) that executes strict logical operations against parsed JSON metadata:

**Security Header Rules** (`security-headers.ts`):
- Missing/malformed HSTS
- Missing/malformed CSP
- Missing X-Frame-Options
- Missing X-Content-Type-Options
- Missing X-XSS-Protection
- Missing Referrer-Policy
- Missing Permissions-Policy

**Cookie Security Rules** (`cookies.ts`):
- Missing Secure flag
- Missing HttpOnly flag
- Missing SameSite attribute
- Invalid SameSite=None without Secure
- Excessive expiration times

**Content Security Rules** (`content.ts`):
- Mixed content detection
- Insecure form actions
- External JavaScript from untrusted domains

**Information Leakage Rules** (`info-leakage.ts`):
- Server header version exposure
- X-Powered-By header exposure
- X-AspNet-Version header exposure
- Debug mode indicators
- Cloudflare WAF status

**Every rule must populate the `SecurityEvidence` object with literal strings scraped from the target.**

### 3. LOAD LAYER (Persistent State)

**Location**: `src/backend/load/`

**Component**: `diff-engine.ts`

**Responsibilities**:
- Pure function `calculateScanDelta(previousScan, currentScan)`
- Returns:
  - `newFindings`: Present in current but not previous
  - `resolvedFindings`: Present in previous but not current
  - `stableFindings`: Persisting issues
  - `newAssets`: Newly discovered assets
  - `removedAssets`: Assets no longer present
- Trend calculation: 'improving', 'degrading', 'stable'
- Regression risk scoring (0-100)

### 4. Database Schema

**Location**: `src/backend/core/database-schema.ts`

**Tables**:
- `organizations`: Org profiles with type (Fintech, Healthcare, SaaS, Startup, Ecommerce, Government)
- `scan_jobs`: Scan metadata and status tracking
- `asset_inventory`: Separate asset tracking for historical delta calculations
- `security_findings`: Individual findings with evidence objects
- `security_debt`: Aggregated security debt scores
- `scan_deltas`: Historical comparison data

**Key Design Decision**: Assets and vulnerabilities are tracked separately to enable historical scan delta calculations.

### 5. Context-Aware Risk Profiler

**Location**: `src/backend/transform/risk-profiler.ts`

**Organization Types**:
- **Fintech**: 1.5x critical severity multiplier, PCI-DSS & SOC2 compliance required
- **Healthcare**: 1.5x critical severity multiplier, HIPAA & GDPR compliance required
- **SaaS**: 1.3x critical severity multiplier, SOC2 & GDPR compliance required
- **Startup**: 1.2x critical severity multiplier, no compliance requirements
- **Ecommerce**: 1.4x critical severity multiplier, PCI-DSS, SOC2 & GDPR compliance required
- **Government**: 1.5x critical severity multiplier, SOC2 & GDPR compliance required

**Severity Adjustment Logic**:
- Base severity × org type multiplier
- Authentication-related findings × authentication risk factor
- Payment-related findings × payment risk factor
- Personal data findings × personal data risk factor
- Health data findings (Healthcare only) × health data risk factor

### 6. Security Debt Calculator

**Location**: `src/backend/transform/security-debt-calculator.ts`

**Scoring**:
- CRITICAL: 25 points
- HIGH: 15 points
- MEDIUM: 8 points
- LOW: 3 points
- INFO: 1 point

**Compliance Multipliers**:
- PCI-DSS: 1.2x
- SOC2: 1.1x
- GDPR: 1.1x
- HIPAA: 1.3x

**Output**:
- Total score (0-100)
- Severity counts
- Trend (improving/degrading/stable)
- Compliance flags (PCI-DSS, SOC2, GDPR, HIPAA)
- Priority recommendations

### 7. API Layer

**Location**: `src/backend/api/`

**Endpoints** (`/api/v2/`):
- `POST /scan` - Initiate new scan
- `GET /scan/:id` - Get scan result by ID
- `GET /scans` - Get all scan history
- `GET /scan/:id/delta` - Get scan delta comparison
- `DELETE /scan/:id` - Delete scan result
- `GET /org-types` - Get supported organization types
- `GET /rules` - Get available rules

**Note**: Legacy API endpoints remain at `/api/` for backward compatibility.

### 8. Frontend Dashboard

**Location**: `src/frontend/components/EnterpriseDashboard.tsx`

**View Modes**:

#### Executive Mode
- Security Debt Score with severity breakdown
- Business Risk Panel with compliance status
- Attack Vector Summary
- Priority Actions list

#### Technical Mode
- Asset Surface Navigator (left column):
  - Discovered Pages
  - Cookie Triage
  - Header Maps
  - Endpoint List
- Evidence Inspector (main column):
  - Selected finding details
  - Raw HTTP request/response code blocks
  - Vulnerable line highlighting
  - Remediation steps
  - CWE references
- Scope Coverage Chart:
  - In Scope: Headers, Cookies, TLS, DNS, Technology Fingerprinting, Mixed Content
  - Out of Scope: Active Exploitation, Business Logic, Auth Bypass, Authorization Testing

## Data Models

### Core Types

```typescript
type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

type OrgType = 'Fintech' | 'Healthcare' | 'SaaS' | 'Startup' | 'Ecommerce' | 'Government';

interface SecurityEvidence {
  timestamp: string;
  location: string;
  rawObserved: string;
  reproduciblePayload?: string;
}

interface SecurityFinding {
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

interface AssetInventory {
  targetUrl: string;
  scanId: string;
  scanTime: string;
  orgType: OrgType;
  technologies: Technology[];
  headers: Record<string, string>;
  cookies: Cookie[];
  endpoints: Endpoint[];
  tlsInfo?: TLSInfo;
  dnsRecords?: DNSRecords;
  openPorts?: number[];
  mixedContentViolations?: string[];
}
```

## Installation

```bash
npm install
```

**New Dependencies**:
- `playwright`: Headless browser automation
- `pg`: PostgreSQL client
- `uuid`: UUID generation

**Playwright Setup**:
```bash
npx playwright install chromium
```

## Database Setup

```bash
# Create PostgreSQL database
createdb aegis_x

# Run schema migration
psql aegis_x < src/backend/core/database-schema.ts
```

## Running the Application

### Development
```bash
npm run dev
```

### Backend API Only
```bash
npm run dev:api
```

### Production Build
```bash
npm run build
npm run preview
```

## API Usage Example

```bash
# Initiate a scan
curl -X POST http://localhost:3000/api/v2/scan \
  -H "Content-Type: application/json" \
  -d '{
    "targetUrl": "https://example.com",
    "orgType": "Fintech",
    "scanDepth": "standard"
  }'

# Get scan result
curl http://localhost:3000/api/v2/scan/{scanId}

# Get scan delta
curl http://localhost:3000/api/v2/scan/{scanId}/delta
```

## Key Design Decisions

1. **Zero AI in Backend**: AI is strictly confined to the presentation layer as an async copilot. The backend is a pure deterministic ETL pipeline.

2. **Separate Asset/Vuln Tracking**: Assets and vulnerabilities are tracked in separate tables to enable historical delta calculations.

3. **Context-Aware Risk Profiling**: Severity is adjusted based on organization type and data profile (e.g., missing HttpOnly on a FinTech balance page escalates to HIGH).

4. **Evidence-Based Findings**: Every finding includes literal raw evidence from the target, not generic explanations.

5. **Graceful Degradation**: Third-party script failures don't fail the entire scan.

6. **Modular Rules Engine**: Rules are file-based and can be extended without modifying core logic.

## Compliance Mapping

| Standard | Relevant Rules |
|----------|----------------|
| PCI-DSS | SEC-001, SEC-002, COOKIE-001, COOKIE-002, COOKIE-003 |
| SOC2 | All security header and cookie rules |
| GDPR | COOKIE-001, COOKIE-002, COOKIE-003, INFO-001, INFO-002 |
| HIPAA | All critical/high severity rules |

## Future Enhancements

1. **PostgreSQL Integration**: Replace in-memory storage with PostgreSQL
2. **Authentication**: Multi-tenant support with user authentication
3. **Scheduled Scans**: Automated periodic scanning
4. **Alerting**: Integration with Slack, PagerDuty, etc.
5. **Reporting**: PDF/CSV export capabilities
6. **AI Copilot**: Async AI integration for remediation summaries (presentation layer only)

## License

Enterprise-grade security platform. See LICENSE for details.
