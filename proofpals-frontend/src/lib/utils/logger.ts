// src/lib/utils/logger.ts
const SENSITIVE_KEYS = ['secretKey', 'seed', 'token', 'signature'];

export function safeLog(data: any) {
  if (import.meta.env.MODE === 'production') return;
  
  const sanitized = JSON.parse(JSON.stringify(data, (key, value) => {
    if (SENSITIVE_KEYS.some(k => key.toLowerCase().includes(k))) {
      return '[REDACTED]';
    }
    return value;
  }));
  
  console.log(sanitized);
}