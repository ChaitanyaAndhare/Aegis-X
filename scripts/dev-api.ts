import '../src/server/env'

const { serve } = await import('@hono/node-server')
const { logOpenRouterKeyStatus } = await import('../src/lib/aegis/ai')
const { default: app } = await import('../src/server/index')

logOpenRouterKeyStatus()

const port = Number(process.env.PORT) || 8787

console.log(`AEGIS API → port ${port}`)

serve({
  fetch: app.fetch,
  port,
})