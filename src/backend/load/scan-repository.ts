/**
 * Load layer: in-memory history + optional PostgreSQL persistence
 */

import type { ScanResult } from '../core/types'
import { schema } from '../core/database-schema'

const memoryByTarget = new Map<string, ScanResult>()
const memoryByScanId = new Map<string, ScanResult>()

function normalizeTarget(url: string): string {
  try {
    const u = new URL(url)
    return `${u.protocol}//${u.host}${u.pathname.replace(/\/$/, '') || ''}`
  } catch {
    return url.trim().toLowerCase()
  }
}

let pgPool: import('pg').Pool | null = null
let schemaReady = false

async function getPool(): Promise<import('pg').Pool | null> {
  const url = process.env.DATABASE_URL?.trim()
  if (!url) return null
  if (!pgPool) {
    const { Pool } = await import('pg')
    pgPool = new Pool({ connectionString: url, ssl: process.env.DATABASE_SSL === 'true' ? { rejectUnauthorized: false } : undefined })
  }
  if (!schemaReady) {
    await pgPool.query(schema)
    schemaReady = true
  }
  return pgPool
}

export function getPreviousScanForTarget(targetUrl: string): ScanResult | null {
  return memoryByTarget.get(normalizeTarget(targetUrl)) ?? null
}

export function getScanById(scanId: string): ScanResult | null {
  return memoryByScanId.get(scanId) ?? null
}

export function listScans(limit = 50): ScanResult[] {
  return [...memoryByScanId.values()]
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
    .slice(0, limit)
}

export async function persistScanResult(result: ScanResult): Promise<void> {
  const key = normalizeTarget(result.assetInventory.targetUrl)
  memoryByTarget.set(key, result)
  memoryByScanId.set(result.scanId, result)

  const pool = await getPool()
  if (!pool) return

  const client = await pool.connect()
  try {
    await client.query('BEGIN')

    await client.query(
      `INSERT INTO scan_jobs (id, target_url, org_type, scan_depth, status, started_at, completed_at, duration_seconds)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        result.scanId,
        result.assetInventory.targetUrl,
        result.request.orgType,
        result.request.scanDepth,
        result.status,
        result.timestamp,
        result.timestamp,
        result.duration,
      ],
    )

    await client.query(
      `INSERT INTO asset_inventory (scan_id, target_url, scan_time, technologies, headers, cookies, endpoints, tls_info, dns_records, open_ports, mixed_content_violations)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        result.scanId,
        result.assetInventory.targetUrl,
        result.assetInventory.scanTime,
        JSON.stringify(result.assetInventory.technologies),
        JSON.stringify(result.assetInventory.headers),
        JSON.stringify(result.assetInventory.cookies),
        JSON.stringify(result.assetInventory.endpoints),
        JSON.stringify(result.assetInventory.tlsInfo ?? null),
        JSON.stringify(result.assetInventory.dnsRecords ?? null),
        result.assetInventory.openPorts ?? null,
        result.assetInventory.mixedContentViolations ?? null,
      ],
    )

    for (const finding of result.findings) {
      await client.query(
        `INSERT INTO security_findings (id, scan_id, rule_id, title, description, base_severity, contextual_severity, evidence, remediation_steps, cwe_id)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [
          finding.id,
          result.scanId,
          finding.ruleId,
          finding.title,
          finding.description,
          finding.baseSeverity,
          finding.contextualSeverity,
          JSON.stringify(finding.evidence),
          finding.remediationSteps,
          finding.cweId ?? null,
        ],
      )
    }

    const debt = result.securityDebt
    await client.query(
      `INSERT INTO security_debt (scan_id, total_score, critical_count, high_count, medium_count, low_count, info_count, trend, compliance_pci_dss, compliance_soc2, compliance_gdpr, compliance_hipaa)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
      [
        result.scanId,
        debt.totalScore,
        debt.criticalCount,
        debt.highCount,
        debt.mediumCount,
        debt.lowCount,
        debt.infoCount,
        debt.trend,
        debt.complianceFlags.pciDss,
        debt.complianceFlags.soc2,
        debt.complianceFlags.gdpr,
        debt.complianceFlags.hipaa,
      ],
    )

    if (result.delta) {
      await client.query(
        `INSERT INTO scan_deltas (scan_id, new_findings, resolved_findings, stable_findings)
         VALUES ($1, $2, $3, $4)`,
        [
          result.scanId,
          result.delta.newFindings.map((f) => f.id),
          result.delta.resolvedFindings.map((f) => f.id),
          result.delta.stableFindings.map((f) => f.id),
        ],
      )
    }

    await client.query('COMMIT')
  } catch (err) {
    await client.query('ROLLBACK')
    console.error('PostgreSQL persist failed (in-memory copy retained):', err)
  } finally {
    client.release()
  }
}
