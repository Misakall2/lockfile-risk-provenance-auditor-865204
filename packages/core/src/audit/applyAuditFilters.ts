import type { AuditLockfileFilters } from '../public/ClientInputs.js';
import type { AuditUpgradeSuggestion, AuditVulnerabilityMatch } from '../public/ClientResults.js';

export interface AuditFilterResult {
  readonly matches: readonly AuditVulnerabilityMatch[];
  readonly upgrades: readonly AuditUpgradeSuggestion[];
}

/**
 * Applies report filters. Component matches the entry or advisory package
 * name; path matches any package name along the dependency path; fixStatus
 * matches the upgrade suggestion state (or "mitigated" match status).
 */
export function applyAuditFilters(
  matches: readonly AuditVulnerabilityMatch[],
  upgrades: readonly AuditUpgradeSuggestion[],
  filters: AuditLockfileFilters | undefined,
): AuditFilterResult {
  if (filters === undefined) return { matches, upgrades };
  const upgradesByMatch = new Map(upgrades.map((upgrade) => [upgrade.matchId, upgrade]));

  const kept = matches.filter((match) => {
    if (
      filters.component !== undefined &&
      match.entry.name !== filters.component &&
      match.package !== filters.component
    ) {
      return false;
    }
    if (
      filters.path !== undefined &&
      !match.dependencyPaths.some((path) =>
        path.packages.some((item) => item.name.includes(filters.path as string)),
      )
    ) {
      return false;
    }
    if (filters.fixStatus !== undefined) {
      if (filters.fixStatus === 'mitigated') return match.status === 'mitigated';
      return upgradesByMatch.get(match.id)?.status === filters.fixStatus;
    }
    return true;
  });

  const keptIds = new Set(kept.map((match) => match.id));
  return {
    matches: kept,
    upgrades: upgrades.filter((upgrade) => keptIds.has(upgrade.matchId)),
  };
}
