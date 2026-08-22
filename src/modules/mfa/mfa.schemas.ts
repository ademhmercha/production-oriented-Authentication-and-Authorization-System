import { z } from 'zod';

export const mfaEnrollSchema = z.object({}).strict();

export const mfaVerifyEnrollSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Must be a 6-digit code'),
});

export const mfaLoginVerifySchema = z.object({
  mfa_challenge_id: z.string().uuid(),
  code: z.string().regex(/^\d{6}$/, 'Must be a 6-digit code'),
});

export const mfaDisableSchema = z.object({
  code: z.string().regex(/^\d{6}$/, 'Must be a 6-digit code'),
});
