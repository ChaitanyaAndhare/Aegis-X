/**
 * Backend API Routes
 * Hono-based API endpoints for scan initiation, results retrieval, and history
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { ScanService, createScanService } from './scan-service';
import { ScanRequest } from '../core/types';

// In-memory storage for scan results (in production, use PostgreSQL)
const scanResults = new Map<string, any>();
const scanServicePromise = createScanService();

const api = new Hono();

// Enable CORS
api.use('*', cors());

/**
 * Health check endpoint
 */
api.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: new Date().toISOString() });
});

/**
 * Initiate a new scan
 * POST /api/scan
 */
api.post('/scan', async (c) => {
  try {
    const body = await c.req.json();
    const scanRequest: ScanRequest = {
      targetUrl: body.targetUrl,
      orgType: body.orgType || 'SaaS',
      scanDepth: body.scanDepth || 'standard',
      includeSubdomains: body.includeSubdomains || false,
      maxPages: body.maxPages || 10
    };

    // Validate URL
    try {
      new URL(scanRequest.targetUrl);
    } catch {
      return c.json({ error: 'Invalid URL' }, 400);
    }

    const scanService = await scanServicePromise;
    const result = await scanService.executeScan(scanRequest);

    // Store result
    scanResults.set(result.scanId, result);

    return c.json(result);
  } catch (error) {
    console.error('Scan error:', error);
    return c.json(
      { error: 'Scan failed', message: error instanceof Error ? error.message : 'Unknown error' },
      500
    );
  }
});

/**
 * Get scan result by ID
 * GET /api/scan/:id
 */
api.get('/scan/:id', (c) => {
  const scanId = c.req.param('id');
  const result = scanResults.get(scanId);

  if (!result) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  return c.json(result);
});

/**
 * Get all scan history
 * GET /api/scans
 */
api.get('/scans', (c) => {
  const scans = Array.from(scanResults.values()).sort(
    (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
  );

  return c.json({ scans, count: scans.length });
});

/**
 * Get scan delta comparison
 * GET /api/scan/:id/delta
 */
api.get('/scan/:id/delta', (c) => {
  const scanId = c.req.param('id');
  const result = scanResults.get(scanId);

  if (!result) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  if (!result.delta) {
    return c.json({ error: 'No delta available' }, 404);
  }

  return c.json(result.delta);
});

/**
 * Delete a scan result
 * DELETE /api/scan/:id
 */
api.delete('/scan/:id', (c) => {
  const scanId = c.req.param('id');
  const deleted = scanResults.delete(scanId);

  if (!deleted) {
    return c.json({ error: 'Scan not found' }, 404);
  }

  return c.json({ message: 'Scan deleted successfully' });
});

/**
 * Get supported organization types
 * GET /api/org-types
 */
api.get('/org-types', (c) => {
  return c.json({
    orgTypes: ['Fintech', 'Healthcare', 'SaaS', 'Startup', 'Ecommerce', 'Government']
  });
});

/**
 * Get available rules
 * GET /api/rules
 */
api.get('/rules', async (c) => {
  const scanService = await scanServicePromise;
  // Note: This would need to be exposed from the rules engine
  return c.json({ rules: [] });
});

export default api;
