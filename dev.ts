import { serve } from '@hono/node-server'
import app from './src/app'

const port = 3000

console.log(`🚀 Server running on http://localhost:${port}`)
console.log(`📝 Test endpoint: POST http://localhost:${port}/api/auth/verify`)

serve({
  fetch: app.fetch,
  port,
})