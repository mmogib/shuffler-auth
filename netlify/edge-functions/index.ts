import { Hono } from 'https://esm.sh/hono@4.6.14'
import { cors } from 'https://esm.sh/hono@4.6.14/cors'

// We need to manually implement handle for Netlify
// since we can't use the JSR version
function handle(app: Hono) {
  return async (request: Request, context: any) => {
    // Add Netlify context to the environment
    const response = await app.fetch(request, {
      context,
    })
    return response
  }
}

// App Config (renamed from 'config' to 'appConfig')
const getEnv = (key: string): string => {
  return (Deno as any).env.get(key) || ''
}

const appConfig = {
  jwtSecret: getEnv('JWT_SECRET') || 'your-super-secret-jwt-key',
  apiEndpoint: getEnv('API_ENDPOINT') || 'https://mshahrani.website',
  jwtExpiresIn: 30 * 24 * 60 * 60,
}

// JWT utilities
function base64urlEncode(str: string): string {
  const base64 = btoa(str)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

async function hmacSha256(message: string, secret: string): Promise<string> {
  const encoder = new TextEncoder()
  const keyData = encoder.encode(secret)
  const messageData = encoder.encode(message)
  
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  )
  
  const signature = await crypto.subtle.sign('HMAC', key, messageData)
  const signatureArray = Array.from(new Uint8Array(signature))
  const signatureString = String.fromCharCode(...signatureArray)
  
  return base64urlEncode(signatureString)
}

async function generateToken(user: any, code: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  
  const payload = {
    email: user.email,
    name: user.name,
    code: code,
    iat: now,
    exp: now + appConfig.jwtExpiresIn,
  }
  
  const header = { alg: 'HS256', typ: 'JWT' }
  
  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))
  
  const signature = await hmacSha256(
    `${encodedHeader}.${encodedPayload}`,
    appConfig.jwtSecret
  )
  
  return `${encodedHeader}.${encodedPayload}.${signature}`
}

async function verifyToken(token: string): Promise<any | null> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    
    const [encodedHeader, encodedPayload, signature] = parts
    
    const expectedSignature = await hmacSha256(
      `${encodedHeader}.${encodedPayload}`,
      appConfig.jwtSecret
    )
    
    if (signature !== expectedSignature) return null
    
    const payloadJson = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'))
    const payload = JSON.parse(payloadJson)
    
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) return null
    
    return payload
  } catch {
    return null
  }
}

// Create app
const app = new Hono()

// CORS middleware
app.use('/*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
}))

// Routes
app.get('/', (c) => {
  return c.json({
    status: 'ok',
    message: 'Shuffler Auth API',
    version: '1.0.0',
  })
})

app.post('/api/auth/verify', async (c) => {
  try {
    const body = await c.req.json()
    const { code } = body

    if (!code) {
      return c.json({ error: 'Access code is required' }, 400)
    }

    const apiUrl = `${appConfig.apiEndpoint}/api/shufflerusers/${encodeURIComponent(code)}.json`
    console.log('Verifying code:', code)

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })

    if (!response.ok) {
      console.error('API request failed:', response.status)
      return c.json({ error: 'Failed to verify access code' }, 500)
    }

    const apiData = await response.json()
    console.log('API Response:', apiData)

    if (!apiData.success) {
      return c.json(
        { 
          error: 'Access code not authorized',
          message: apiData.message || 'Please contact an administrator.'
        },
        403
      )
    }

    const user = apiData.data

    if (!user.email) {
      return c.json({ error: 'User record missing email information' }, 500)
    }

    const token = await generateToken(user, code)

    return c.json({
      success: true,
      token,
      user: {
        email: user.email,
        name: user.name,
      },
      expiresIn: '30 days',
    })

  } catch (error) {
    console.error('Error in verify endpoint:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

app.get('/api/auth/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json({ error: 'Missing or invalid authorization header' }, 401)
    }

    const token = authHeader.substring(7)
    const payload = await verifyToken(token)

    if (!payload) {
      return c.json({ error: 'Invalid or expired token' }, 401)
    }

    return c.json({
      success: true,
      user: {
        email: payload.email,
        name: payload.name,
      },
    })

  } catch (error) {
    console.error('Error in me endpoint:', error)
    return c.json({ error: 'Internal server error' }, 500)
  }
})

export default handle(app)

// Edge function configuration (note: renamed to avoid conflict)
export const config = {
  path: '/*'
}