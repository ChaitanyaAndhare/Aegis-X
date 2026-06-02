import '../src/server/env'

const { serve } = await import('@hono/node-server')
const { logOpenRouterKeyStatus } = await import('../src/lib/aegis/ai')
const { default: app } = await import('../src/server/index')

logOpenRouterKeyStatus()
const port = 8787
console.log(`AEGIS API → http://127.0.0.1:${port}`)
serve({ fetch: app.fetch, port })
