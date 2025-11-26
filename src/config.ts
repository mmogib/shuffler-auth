// Runtime detection
export const isNode = typeof process !== 'undefined' && process.versions?.node

// Get environment variable (works in both Node and Deno)
export function getEnv(key: string): string {
  if (isNode) {
    // Node.js
    return process.env[key] || ''
  } else {
    // Deno
    return (Deno as any).env.get(key) || ''
  }
}

export const config = {
  jwtSecret: getEnv('JWT_SECRET') || 'your-super-secret-jwt-key-change-this-in-production',
  apiEndpoint: getEnv('API_ENDPOINT') || 'https://mshahrani.website',
  jwtExpiresIn: 30 * 24 * 60 * 60, // 30 days in seconds
}