import argon2 from 'argon2';
import { loadConfig } from '../../config';
import { ValidationError } from '../../common/errors';

/**
 * Password hashing + strength policy.
 *
 * SECURITY DECISION: Argon2id (memory-hard, OWASP-recommended first choice).
 * Parameters follow current guidance (64MB memory, t=3).
 */
const ARGON2_OPTS: argon2.Options = {
  type: argon2.argon2id,
  memoryCost: 65_536, // KiB = 64 MiB
  timeCost: 3,
  parallelism: 4,
};

export async function hashPassword(plain: string): Promise<string> {
  return argon2.hash(plain, ARGON2_OPTS);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  try {
    return await argon2.verify(hash, plain);
  } catch {
    // Malformed hash in DB should behave like a failed login.
    return false;
  }
}

/** Small sample of commonly leaked passwords - extendable via external list. */
const COMMON_PASSWORDS = new Set([
  'password',
  'password1',
  'password123',
  '12345678',
  '123456789',
  '1234567890',
  'qwerty123',
  'qwertyuiop',
  'letmein123',
  'welcome123',
  'admin123456',
  'iloveyou1',
  'sunshine1',
  'princess1',
  'football1',
  'abc123456',
]);

export interface PasswordPolicyResult {
  valid: boolean;
  errors: Record<string, string>;
}

export function checkPasswordPolicy(password: string): PasswordPolicyResult {
  const errors: Record<string, string> = {};
  const minLength = loadConfig().PASSWORD_MIN_LENGTH;

  if (typeof password !== 'string' || password.length < minLength) {
    errors.password = `Must be at least ${minLength} characters`;
  }
  if (!/[a-z]/.test(password)) {
    errors.password ??= '';
    errors.password += ' Must contain a lowercase letter.';
  }
  if (!/[A-Z]/.test(password)) {
    errors.password ??= '';
    errors.password += ' Must contain an uppercase letter.';
  }
  if (!/\d/.test(password)) {
    errors.password ??= '';
    errors.password += ' Must contain a digit.';
  }
  if (/^\s|\s$/.test(password)) {
    errors.password ??= '';
    errors.password += ' Must not start or end with whitespace.';
  }
  if (COMMON_PASSWORDS.has((password ?? '').toLowerCase())) {
    errors.password = 'This password is too common.';
  }

  if (Object.keys(errors).length > 0) throw new ValidationError('Password does not meet the policy', errors);
  return { valid: true, errors: {} };
}
