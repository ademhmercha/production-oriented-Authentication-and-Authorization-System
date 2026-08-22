import { createHash } from 'node:crypto';
import { RiskEngine, RiskEvaluation, LoginRiskInput, RiskLevel } from './risk.types';
import { RedisService } from '../../infrastructure/redis/redis.service';
import { loadConfig } from '../../config';

/**
 * Rules-based risk engine (default implementation).
 *
 * Signals:
 *  - failed login attempts in the last window (Redis counter)
 *  - login frequency (distinct IPs / attempts per user per hour)
 *  - new device fingerprint
 *  - placeholder hook for impossible-travel: IP prefix change with short
 *    time delta is flagged as medium until a geo provider is integrated.
 */
export class RulesRiskEngine implements RiskEngine {
  constructor(private readonly redis: RedisService) {}

  async evaluateLogin(input: LoginRiskInput): Promise<RiskEvaluation> {
    const config = loadConfig();
    const signals: RiskEvaluation['signals'] = [];
    let score = 0;

    // Signal 1: recent failed attempts for this user.
    const failedKey = RedisService.key('risk', 'failed', input.userId);
    const failedCount = Number((await this.redis.get(failedKey)) ?? '0');
    if (failedCount >= config.RISK_FAILED_LOGINS_THRESHOLD) {
      score += 30;
      signals.push({ signal: 'failed_logins', detail: `${failedCount} recent failures` });
    }

    // Signal 2: distinct-IP frequency over the last hour.
    const ipKey = RedisService.key('risk', 'ips', input.userId);
    if (input.ip) {
      await this.redis.setAdd(ipKey, input.ip);
      await this.redis.setExpire(ipKey, 3600);
      const ipCount = await this.redis.setSize(ipKey);
      if (ipCount >= 5) {
        score += 20;
        signals.push({ signal: 'ip_frequency', detail: `${ipCount} distinct IPs in 1h` });
      }
    }

    // Signal 3: unknown device.
    if (!input.knownDevice) {
      score += 15;
      signals.push({ signal: 'new_device' });
    }

    // Signal 4: impossible travel placeholder (last-seen IP prefix change < 5 min).
    if (input.ip && input.userAgent) {
      const seenKey = RedisService.key(
        'risk',
        'geo',
        input.userId,
        deviceFingerprint(input.userAgent),
      );
      const lastPrefix = await this.redis.get(seenKey);
      const currentPrefix = input.ip.split('.').slice(0, 2).join('.');
      if (lastPrefix && lastPrefix !== currentPrefix) {
        score += 25;
        signals.push({
          signal: 'impossible_travel_placeholder',
          detail: `ip-prefix ${lastPrefix} -> ${currentPrefix}`,
        });
      }
      await this.redis.set(seenKey, currentPrefix, 300);
    }

    const level: RiskLevel = score >= 50 ? 'high' : score >= 20 ? 'medium' : 'low';
    return { level, score, signals };
  }
}

export function deviceFingerprint(userAgent: string): string {
  return createHash('sha256').update(userAgent).digest('hex').slice(0, 16);
}
