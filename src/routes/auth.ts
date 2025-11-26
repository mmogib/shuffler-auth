import { Hono } from 'hono'
import { config } from '../config'
import { generateToken } from '../services/jwt'
import type { ApiResponse, VerifyRequest, AuthResponse, ErrorResponse } from '../types'

const auth = new Hono()

auth.post('/verify', async (c) => {
  try {
    const body = await c.req.json<VerifyRequest>()
    const { code } = body

    if (!code) {
      return c.json<ErrorResponse>(
        { error: 'Access code is required' },
        400
      )
    }

    // Call your custom API
    const apiUrl = `${config.apiEndpoint}/api/shufflerusers/${encodeURIComponent(code)}.json`
    console.log('Verifying code:', code)
    console.log('API URL:', apiUrl)

    const response = await fetch(apiUrl, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })

    if (!response.ok) {
      console.error('API request failed:', response.status)
      return c.json<ErrorResponse>(
        { error: 'Failed to verify access code' },
        500
      )
    }

    const apiData = await response.json() as ApiResponse
    console.log('API Response:', apiData)

    if (!apiData.success) {
      return c.json<ErrorResponse>(
        { 
          error: 'Access code not authorized',
          message: apiData.message || 'Please contact an administrator.'
        },
        403
      )
    }

    const user = apiData.data

    if (!user.email) {
      return c.json<ErrorResponse>(
        { error: 'User record missing email information' },
        500
      )
    }

    // Generate JWT token
    const token = await generateToken(user, code)

    // Return success response
    return c.json<AuthResponse>({
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
    return c.json<ErrorResponse>(
      { error: 'Internal server error' },
      500
    )
  }
})

// Optional: endpoint to verify if a token is valid
auth.get('/me', async (c) => {
  try {
    const authHeader = c.req.header('Authorization')
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return c.json<ErrorResponse>(
        { error: 'Missing or invalid authorization header' },
        401
      )
    }

    const token = authHeader.substring(7)
    const { verifyToken } = await import('../services/jwt')
    const payload = await verifyToken(token)

    if (!payload) {
      return c.json<ErrorResponse>(
        { error: 'Invalid or expired token' },
        401
      )
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
    return c.json<ErrorResponse>(
      { error: 'Internal server error' },
      500
    )
  }
})

export default auth