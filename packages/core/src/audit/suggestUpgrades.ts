import type {
  AuditLockEntry,
  AuditUpgradeSuggestion,
  AuditVulnerabilityMatch,
} from '../public/ClientResults.js';
import type { AuditAdvisoryDatabase, AuditAdvisoryRecord } from './AuditDatabase.js';
import { compareVersionStrings, parseSemver, satisfiesRange } from './semver.js';

/**
 * Builds upgrade suggestions for confirmed matches. A candidate is only
 * "ready" when it satisfies every complementary constraint that selected the
 * locked entry (importer and dependent ranges); candidates that resolve
 * higher but would break the lock are reported as "constrained" with the
 * blocking ranges instead of being presented as a bare version number.
 */
export function suggestUpgrades(
  matches: readonly AuditVulnerabilityMatch[],
  entries: readonly AuditLockEntry[],
  database: AuditAdvisoryDatabase,
): AuditUpgradeSuggestion[] {
  const entriesByKey = new Map(entries.map((entry) => [entry.key, entry]));
  const advisoriesById = new Map(database.advisories.map((advisory) => [advisory.id, advisory]));
  const suggestions: AuditUpgradeSuggestion[] = [];

  for (const match of matches) {
    if (match.status !== 'confirmed') continue;
    const entry = entriesByKey.get(match.entry.key);
    const advisory = advisoriesById.get(match.advisory.id);
    if (entry === undefined || advisory === undefined) continue;
    suggestions.push(buildSuggestion(match, entry, advisory));
  }
  return suggestions.sort((left, right) => left.matchId.localeCompare(right.matchId));
}

function buildSuggestion(
  match: AuditVulnerabilityMatch,
  entry: AuditLockEntry,
  advisory: AuditAdvisoryRecord,
): AuditUpgradeSuggestion {
  const base = {
    matchId: match.id,
    entry: {
      key: entry.key,
      name: entry.name,
      ...(entry.version === undefined ? {} : { version: entry.version }),
    },
    ...(entry.version === undefined ? {} : { currentVersion: entry.version }),
  };
  const candidates = candidateVersions(entry, advisory);
  if (candidates.length === 0) {
    return {
      ...base,
      status: 'unavailable',
      blockedBy: [],
      summary: `No fixed version of ${entry.name} is known for ${advisory.id}; mitigation requires a manual decision.`,
    };
  }
  const constraints = entry.declaredRanges;
  const ready = candidates.find((candidate) =>
    constraints.every((range) => satisfiesRange(candidate, range.specifier) === true),
  );
  if (ready !== undefined) {
    return {
      ...base,
      candidate: ready,
      status: 'ready',
      blockedBy: [],
      summary: `Upgrade ${entry.name} from ${entry.version ?? 'unknown'} to ${ready}; the candidate satisfies every locked constraint.`,
    };
  }
  const candidate = candidates[0] as string;
  const blockedBy = constraints
    .filter((range) => satisfiesRange(candidate, range.specifier) !== true)
    .map((range) => ({ dependent: range.declaredBy, specifier: range.specifier }))
    .sort((left, right) =>
      `${left.dependent}\0${left.specifier}`.localeCompare(
        `${right.dependent}\0${right.specifier}`,
      ),
    );
  return {
    ...base,
    candidate,
    status: 'constrained',
    blockedBy,
    summary: `Upgrade ${entry.name} to ${candidate} fixes ${advisory.id} but conflicts with ${blockedBy.length} locked constraint(s); the hint is downgraded until dependents allow it.`,
  };
}

function candidateVersions(entry: AuditLockEntry, advisory: AuditAdvisoryRecord): string[] {
  const pool = [...new Set([...advisory.fixed, ...advisory.knownVersions])];
  const current = entry.version === undefined ? undefined : parseSemver(entry.version);
  return pool
    .filter((version) => {
      if (parseSemver(version) === undefined) return false;
      if (current !== undefined && compareVersionStrings(version, entry.version as string) <= 0) {
        return false;
      }
      return advisory.affected.every((range) => satisfiesRange(version, range) === false);
    })
    .sort(compareVersionStrings);
}
