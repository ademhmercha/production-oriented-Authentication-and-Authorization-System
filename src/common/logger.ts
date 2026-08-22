import pino from 'pino';
import { loadConfig } from '../config';

export const logger = pino({
  level: loadConfig().LOG_LEVEL,
  redact: {
    paths: [
      'req.headers.authorization',
      'req.headers.cookie',
      '*.password',
      '*.passwordHash',
      '*.client_secret',
      '*.clientSecret',
      '*.refresh_token',
      '*.refreshToken',
      '*.code_verifier',
      '*.secret',
    ],
    censor: '[REDACTED]',
  },
  base: { service: process.env.SERVICE_NAME ?? 'auth-server' },
});
