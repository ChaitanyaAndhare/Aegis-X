/**
 * PostgreSQL Database Schema for AEGIS-X
 * Separate tables for assets, vulnerabilities, and scan history
 */

export const schema = `
-- Organizations
CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  org_type VARCHAR(50) NOT NULL CHECK (org_type IN ('Fintech', 'Healthcare', 'SaaS', 'Startup', 'Ecommerce', 'Government')),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Scan Jobs
CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id UUID REFERENCES organizations(id),
  target_url TEXT NOT NULL,
  org_type VARCHAR(50) NOT NULL,
  scan_depth VARCHAR(20) NOT NULL CHECK (scan_depth IN ('basic', 'standard', 'deep')),
  status VARCHAR(20) NOT NULL CHECK (status IN ('pending', 'running', 'completed', 'failed', 'partial')),
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  duration_seconds INTEGER,
  error_message TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Asset Inventory
CREATE TABLE IF NOT EXISTS asset_inventory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id),
  target_url TEXT NOT NULL,
  scan_time TIMESTAMP WITH TIME ZONE NOT NULL,
  technologies JSONB,
  headers JSONB,
  cookies JSONB,
  endpoints JSONB,
  tls_info JSONB,
  dns_records JSONB,
  open_ports INTEGER[],
  mixed_content_violations TEXT[],
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW,
  UNIQUE(scan_id, target_url)
);

-- Security Findings
CREATE TABLE IF NOT EXISTS security_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id),
  asset_id UUID REFERENCES asset_inventory(id),
  rule_id VARCHAR(255) NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  base_severity VARCHAR(20) NOT NULL CHECK (base_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  contextual_severity VARCHAR(20) NOT NULL CHECK (contextual_severity IN ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
  evidence JSONB NOT NULL,
  remediation_steps TEXT[],
  cwe_id VARCHAR(20),
  cvss_score DECIMAL(3,1),
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW
);

-- Security Debt Scores
CREATE TABLE IF NOT EXISTS security_debt (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id),
  total_score INTEGER CHECK (total_score BETWEEN 0 AND 100),
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  trend VARCHAR(20) CHECK (trend IN ('improving', 'degrading', 'stable')),
  compliance_pci_dss BOOLEAN DEFAULT false,
  compliance_soc2 BOOLEAN DEFAULT false,
  compliance_gdpr BOOLEAN DEFAULT false,
  compliance_hipaa BOOLEAN DEFAULT false,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW
);

-- Scan Deltas (Historical Comparison)
CREATE TABLE IF NOT EXISTS scan_deltas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id),
  previous_scan_id UUID REFERENCES scan_jobs(id),
  new_findings UUID[],
  resolved_findings UUID[],
  stable_findings UUID[],
  new_assets UUID[],
  removed_assets UUID[],
  timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_scan_jobs_org ON scan_jobs(organization_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_asset_inventory_scan ON asset_inventory(scan_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_scan ON security_findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_severity ON security_findings(contextual_severity);
CREATE INDEX IF NOT EXISTS idx_security_findings_rule ON security_findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_security_debt_scan ON security_debt(scan_id);
`;

export const migrations = [
  {
    version: '001',
    description: 'Initial schema creation',
    up: schema
  }
];
