-- Enterprise deterministic ETL tables (optional; app works with in-memory store without this)

CREATE TABLE IF NOT EXISTS organizations (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name VARCHAR(255) NOT NULL,
  org_type VARCHAR(50) NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_jobs (
  id UUID PRIMARY KEY,
  organization_id UUID REFERENCES organizations(id),
  target_url TEXT NOT NULL,
  org_type VARCHAR(50) NOT NULL,
  scan_depth VARCHAR(20) NOT NULL DEFAULT 'standard',
  status VARCHAR(20) NOT NULL,
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  duration_seconds INTEGER,
  error_message TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS asset_inventory (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
  target_url TEXT NOT NULL,
  scan_time TIMESTAMPTZ NOT NULL,
  technologies JSONB,
  headers JSONB,
  cookies JSONB,
  endpoints JSONB,
  tls_info JSONB,
  dns_records JSONB,
  open_ports INTEGER[],
  mixed_content_violations TEXT[],
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_findings (
  id UUID PRIMARY KEY,
  scan_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
  asset_id UUID REFERENCES asset_inventory(id),
  rule_id VARCHAR(255) NOT NULL,
  title TEXT NOT NULL,
  description TEXT,
  base_severity VARCHAR(20) NOT NULL,
  contextual_severity VARCHAR(20) NOT NULL,
  evidence JSONB NOT NULL,
  remediation_steps TEXT[],
  cwe_id VARCHAR(20),
  cvss_score DECIMAL(3,1),
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS security_debt (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
  total_score INTEGER,
  critical_count INTEGER DEFAULT 0,
  high_count INTEGER DEFAULT 0,
  medium_count INTEGER DEFAULT 0,
  low_count INTEGER DEFAULT 0,
  info_count INTEGER DEFAULT 0,
  trend VARCHAR(20),
  compliance_pci_dss BOOLEAN DEFAULT false,
  compliance_soc2 BOOLEAN DEFAULT false,
  compliance_gdpr BOOLEAN DEFAULT false,
  compliance_hipaa BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS scan_deltas (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id UUID REFERENCES scan_jobs(id) ON DELETE CASCADE,
  previous_scan_id UUID REFERENCES scan_jobs(id),
  new_findings UUID[],
  resolved_findings UUID[],
  stable_findings UUID[],
  new_assets UUID[],
  removed_assets UUID[],
  timestamp TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_created ON scan_jobs(created_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_findings_scan ON security_findings(scan_id);
