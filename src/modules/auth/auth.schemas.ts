import { z } from 'zod';

export const registerSchema = z.object({
  email: z.string().trim().toLowerCase().email('Must be a valid email'),
  password: z.string().min(1, 'Password is required'),
  first_name: z.string().trim().min(1).max(100).optional(),
  last_name: z.string().trim().min(1).max(100).optional(),
});

export const loginSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
  password: z.string().min(1),
});

export const refreshSchema = z.object({
  refresh_token: z.string().min(32),
});

export const logoutSchema = z.object({
  refresh_token: z.string().min(32).optional(),
  all_sessions: z.boolean().optional(),
});

export const verifyEmailSchema = z.object({
  token: z.string().min(20),
});

export const forgotPasswordSchema = z.object({
  email: z.string().trim().toLowerCase().email(),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(20),
  password: z.string().min(1),
});
