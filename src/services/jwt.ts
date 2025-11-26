import { config } from '../config'
import type { User, JWTPayload } from '../types'

// Simple base64url encoding
function base64urlEncode(str: string): string {
  const base64 = btoa(str)
  return base64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}

// Simple HMAC-SHA256 (using Web Crypto API - works in both Node & Deno)
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

export async function generateToken(user: User, code: string): Promise<string> {
  const now = Math.floor(Date.now() / 1000)
  
  const payload: JWTPayload = {
    email: user.email,
    name: user.name,
    code: code,
    iat: now,
    exp: now + config.jwtExpiresIn,
  }
  
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  }
  
  const encodedHeader = base64urlEncode(JSON.stringify(header))
  const encodedPayload = base64urlEncode(JSON.stringify(payload))
  
  const signature = await hmacSha256(
    `${encodedHeader}.${encodedPayload}`,
    config.jwtSecret
  )
  
  return `${encodedHeader}.${encodedPayload}.${signature}`
}

export async function verifyToken(token: string): Promise<JWTPayload | null> {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    
    const [encodedHeader, encodedPayload, signature] = parts
    
    // Verify signature
    const expectedSignature = await hmacSha256(
      `${encodedHeader}.${encodedPayload}`,
      config.jwtSecret
    )
    
    if (signature !== expectedSignature) return null
    
    // Decode payload
    const payloadJson = atob(encodedPayload.replace(/-/g, '+').replace(/_/g, '/'))
    const payload: JWTPayload = JSON.parse(payloadJson)
    
    // Check expiration
    const now = Math.floor(Date.now() / 1000)
    if (payload.exp < now) return null
    
    return payload
  } catch {
    return null
  }
}