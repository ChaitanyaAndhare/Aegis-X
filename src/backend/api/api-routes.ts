/**
 * Enterprise ETL API (/api/v2)
 */

import { Hono } from 'hono'
import { cors } from 'hono/cors'
import type { ScanRequest } from '../core/types'
import { createScanService } from './scan-service'
import { RulesEngine } from '../rules'
import { getScanById, listScans } from '../load/scan-repository'

const scanService = createScanService()
const rulesEngine = new RulesEngine()

const api = new Hono()
api.use('*', cors())

api.get('/health', (c) =>
  c.json({
    status: 'ok',
    pipeline: 'extract-transform-load',
    aiInBackend: false,
    timestamp: new Date().toISOString(),
  }),
)

api.post('/scan', async (c) => {
  try {
    const body = await c.req.json()
    const scanRequest: ScanRequest = {
      targetUrl: body.targetUrl,
      orgType: body.orgType || 'SaaS',
      scanDepth: body.scanDepth || 'standard',
      includeSubdomains: body.includeSubdomains || false,
      maxPages: body.maxPages || 10,
    }

    try {
      new URL(scanRequest.targetUrl)
    } catch {
      return c.json({ error: 'Invalid URL' }, 400)
    }

    const result = await scanService.executeScan(scanRequest)
    return c.json(result, result.status === 'failed' ? 500 : 200)
  } catch (error) {
    console.error('Scan error:', error)
    return c.json(
      { error: 'Scan failed', message: error instanceof Error ? error.message : 'Unknown error' },
      500,
    )
  }
})

api.get('/scan/:id', (c) => {
  const result = getScanById(c.req.param('id'))
  if (!result) return c.json({ error: 'Scan not found' }, 404)
  return c.json(result)
})

api.get('/scans', (c) => {
  const scans = listScans()
  return c.json({ scans, count: scans.length })
})

api.get('/scan/:id/delta', (c) => {
  const result = getScanById(c.req.param('id'))
  if (!result?.delta) return c.json({ error: 'No delta available' }, 404)
  return c.json(result.delta)
})

api.delete('/scan/:id', (c) => {
  return c.json({ message: 'Delete not supported in memory mode' })
})

api.get('/org-types', (c) =>
  c.json({
    orgTypes: ['Fintech', 'Healthcare', 'SaaS', 'Startup', 'Ecommerce', 'Government'],
  }),
)

api.get('/rules', (c) => c.json({ rules: rulesEngine.getRules().map((r) => ({ id: r.id, title: r.title, category: r.category, severity: r.severity })) }))

export default api
