/**
 * Risk engine abstraction.
 *
 * Evaluates login/token activity signals and returns a risk level. The
 * interface allows swapping in an external risk engine later; the default
 * implementation uses deterministic local rules.
 */
export type RiskLevel = 'low' | 'medium' | 'high';

export interface LoginRiskInput {
  userId: string;
  ip: string | null;
  userAgent: string | null;
  /** Whether this device fingerprint was seen before for the user. */
  knownDevice: boolean;
}

export interface RiskEvaluation {
  level: RiskLevel;
  score: number;
  signals: Array<{ signal: string; detail?: string }>;
}

export interface RiskEngine {
  evaluateLogin(input: LoginRiskInput): Promise<RiskEvaluation>;
}
