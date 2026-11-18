import type { AuditExceptionInput } from '../public/ClientInputs.js';
import type { AuditExceptionRecord, AuditVulnerabilityMatch } from '../public/ClientResults.js';

export interface AuditExceptionApplication {
  readonly visibleMatches: readonly AuditVulnerabilityMatch[];
  readonly active: readonly AuditExceptionRecord[];
  readonly expired: readonly AuditExceptionRecord[];
  readonly ignoredCount: number;
}

/**
 * Applies review exceptions to matches. An exception suppresses a match only
 * while it is unexpired; expired exceptions are reported and their matches
 * re-enter the visible result set.
 */
export function applyAuditExceptions(
  matches: readonly AuditVulnerabilityMatch[],
  exceptions: readonly AuditExceptionInput[],
  now: Date,
): AuditExceptionApplication {
  const active: AuditExceptionRecord[] = [];
  const expired: AuditExceptionRecord[] = [];
  const suppressed = new Set<string>();

  const sorted = [...exceptions].sort((left, right) =>
    `${left.advisory}\0${left.package ?? ''}\0${left.expiresAt}`.localeCompare(
      `${right.advisory}\0${right.package ?? ''}\0${right.expiresAt}`,
    ),
  );
  for (const exception of sorted) {
    const matched = matches.filter((match) => exceptionApplies(exception, match));
    const expiry = Date.parse(exception.expiresAt);
    const isActive = Number.isFinite(expiry) && expiry > now.getTime();
    const record: AuditExceptionRecord = {
      advisory: exception.advisory,
      ...(exception.package === undefined ? {} : { package: exception.package }),
      reason: exception.reason,
      expiresAt: exception.expiresAt,
      matchedCount: matched.length,
    };
    if (isActive) {
      active.push(record);
      for (const match of matched) suppressed.add(match.id);
    } else {
      expired.push(record);
    }
  }

  return {
    visibleMatches: matches.filter((match) => !suppressed.has(match.id)),
    active,
    expired,
    ignoredCount: suppressed.size,
  };
}

function exceptionApplies(exception: AuditExceptionInput, match: AuditVulnerabilityMatch): boolean {
  const advisoryMatches =
    match.advisory.id === exception.advisory || match.advisory.aliases.includes(exception.advisory);
  if (!advisoryMatches) return false;
  return (
    exception.package === undefined ||
    exception.package === match.package ||
    exception.package === match.entry.name
  );
}
