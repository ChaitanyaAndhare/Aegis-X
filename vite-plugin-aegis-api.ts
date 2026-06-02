import type { IncomingMessage, ServerResponse } from 'node:http'
import type { Plugin } from 'vite'
import path from 'node:path'
import { fileURLToPath } from 'node:url'
import dotenv from 'dotenv'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)))
dotenv.config({ path: path.join(root, '.env') })

function readBody(req: IncomingMessage): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    req.on('data', (c) => chunks.push(c))
    req.on('end', () => resolve(Buffer.concat(chunks)))
    req.on('error', reject)
  })
}

async function sendResponse(nodeRes: ServerResponse, webRes: Response) {
  nodeRes.statusCode = webRes.status
  webRes.headers.forEach((value, key) => {
    if (key === 'transfer-encoding') return
    nodeRes.setHeader(key, value)
  })
  if (webRes.body) {
    const reader = webRes.body.getReader()
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read()
        if (done) break
        nodeRes.write(value)
      }
      nodeRes.end()
    }
    await pump()
  } else {
    nodeRes.end()
  }
}

export function aegisApiPlugin(): Plugin {
  let app: { fetch: typeof fetch }

  return {
    name: 'aegis-api',
    async configureServer(server) {
      const { logOpenRouterKeyStatus } = await import('./src/lib/aegis/ai')
      const { default: honoApp } = await import('./src/server/index')
      app = honoApp
      logOpenRouterKeyStatus()
      console.log('[AEGIS] API embedded in Vite dev server (same origin, no port 8787)')

      server.middlewares.use(async (req, res, next) => {
        if (!req.url?.startsWith('/api')) return next()

        try {
          const host = req.headers.host ?? 'localhost'
          const url = `http://${host}${req.url}`
          const method = req.method ?? 'GET'
          const hasBody = method !== 'GET' && method !== 'HEAD'
          const bodyBuf = hasBody ? await readBody(req) : undefined

          const headers = new Headers()
          for (const [key, val] of Object.entries(req.headers)) {
            if (val === undefined) continue
            if (Array.isArray(val)) val.forEach((v) => headers.append(key, v))
            else headers.set(key, val)
          }

          const request = new Request(url, {
            method,
            headers,
            body: bodyBuf?.length ? bodyBuf : undefined,
          })

          const response = await app.fetch(request)
          await sendResponse(res, response)
        } catch (err) {
          console.error('[AEGIS] API middleware error:', err)
          res.statusCode = 500
          res.setHeader('Content-Type', 'application/json')
          res.end(JSON.stringify({ error: 'Internal API error', detail: String(err) }))
        }
      })
    },
  }
}
