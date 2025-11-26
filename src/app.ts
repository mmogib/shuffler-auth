import { Hono } from 'hono'
import { cors } from 'hono/cors'
import auth from './routes/auth'

const app = new Hono()

// CORS middleware
app.use('/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Health check
app.get('/', (c) => {
  return c.json({
    status: 'ok',
    message: 'Shuffler Auth API',
    version: '1.0.0',
  })
})

// Mount auth routes
app.route('/api/auth', auth)

export default app