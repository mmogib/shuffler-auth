export interface User {
  name: string
  email: string
}

export interface ApiResponse {
  success: boolean
  message: string
  data: User
}

export interface JWTPayload {
  email: string
  name: string
  code: string
  iat: number
  exp: number
}

export interface VerifyRequest {
  code: string
}

export interface AuthResponse {
  success: boolean
  token: string
  user: User
  expiresIn: string
}

export interface ErrorResponse {
  error: string
  message?: string
}