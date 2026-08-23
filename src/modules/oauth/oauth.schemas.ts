import { z } from 'zod';

export const authorizeQuerySchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string().min(4),
  redirect_uri: z.string().url(),
  scope: z.string().default('openid'),
  state: z.string().max(512).optional(),
  nonce: z.string().max(512).optional(),
  code_challenge: z.string().min(43).max(128).optional(),
  code_challenge_method: z.enum(['S256', 'plain']).default('S256'),
});

export const tokenFormSchema = z.object({
  grant_type: z.enum(['authorization_code', 'client_credentials', 'refresh_token']),
  code: z.string().optional(),
  redirect_uri: z.string().optional(),
  client_id: z.string().optional(),
  client_secret: z.string().optional(),
  code_verifier: z.string().min(43).max(128).optional(),
  scope: z.string().optional(),
  refresh_token: z.string().min(10).optional(),
});

export const introspectFormSchema = z.object({
  token: z.string().min(10),
});

export const revokeFormSchema = z.object({
  token: z.string().min(10),
});
