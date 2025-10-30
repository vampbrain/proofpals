// src/lib/api/endpoints.ts
export const API_ENDPOINTS = {
    // Health
    health: '/health',
    
    // Auth (when implemented)
    login: '/api/v1/auth/login',
    register: '/api/v1/auth/register',
    refresh: '/api/v1/auth/refresh',
    
    // Submissions
    submissions: '/api/v1/submissions',
    submission: (id: number) => `/api/v1/submissions/${id}`,
    
    // Rings
    rings: '/api/v1/rings',
    ring: (id: number) => `/api/v1/rings/${id}`,
    
    // Credentials & Tokens
    presentCredential: '/api/v1/present-credential',
    publishPublicKey: '/api/v1/reviewer/public-key',
    listPublicKeys: '/api/v1/reviewer/public-keys',
    vetterRegisterCredential: '/api/v1/vetter/register-credential',
    vetterStatistics: '/api/v1/vetter/statistics',
    
    // Voting
    vote: '/api/v1/vote',
    tally: (id: number) => `/api/v1/tally/${id}`,
    
    // Statistics
    statistics: '/api/v1/statistics',
  } as const;