import { basename } from 'node:path';
import { applyAuditExceptions } from '../audit/applyAuditExceptions.js';
import { applyAuditFilters } from '../audit/applyAuditFilters.js';
import { loadAuditDatabase, loadAuditExceptions } from '../audit/loadAuditInputs.js';
import { matchVulnerabilities } from '../audit/matchVulnerabilities.js';
import { normalizeLockEntries } from '../audit/normalizeLockEntries.js';
import { suggestUpgrades } from '../audit/suggestUpgrades.js';
import { detectPackageManager } from '../project/discovery/detectPackageManager.js';
import { discoverProjectRoot } from '../project/discovery/discoverProjectRoot.js';
import { analyzeDependencyGraph } from '../project/lockfile/analyzeDependencyGraph.js';
import { parseProjectLockfile } from '../project/lockfile/parseProjectLockfile.js';
import { loadPackageManifest } from '../project/manifest/loadPackageManifest.js';
import { discoverWorkspaces } from '../project/workspace/discoverWorkspaces.js';
import { selectWorkspaces } from '../project/workspace/selectWorkspaces.js';
import type { AuditLockfileInput } from '../public/ClientInputs.js';
import type { LockfileAuditReport } from '../public/ClientResults.js';

export interface AuditLockfileContext {
  readonly toolVersion: string;
  readonly now: () => Date;
}

export async function auditLockfileRisk(
  input: AuditLockfileInput,
  context: AuditLockfileContext,
): Promise<LockfileAuditReport> {
  const root = await discoverProjectRoot(input.root, input.signal);
  const manifest = await loadPackageManifest(root, input.signal);
  const availableWorkspaces = await discoverWorkspaces(root, manifest, input.signal);
  const selectedWorkspaces = selectWorkspaces(availableWorkspaces, input.workspaces);
  const manager = await detectPackageManager(root, manifest, input.signal);
  const includeDevelopment = input.includeDev ?? true;

  const [database, exceptions] = await Promise.all([
    loadAuditDatabase(input.advisories, input.advisoryDatabaseFile, input.signal),
    loadAuditExceptions(input.exceptions, input.exceptionsFile, input.signal),
  ]);

  const lockfileGraph = await parseProjectLockfile(
    root,
    manager,
    selectedWorkspaces.length === 0
      ? ['.']
      : selectedWorkspaces.map((workspace) => workspace.relativePath),
    input.signal,
  );
  const graphAnalysis =
    lockfileGraph === undefined
      ? undefined
      : analyzeDependencyGraph(lockfileGraph, includeDevelopment);

  const entries =
    lockfileGraph === undefined || graphAnalysis === undefined
      ? []
      : normalizeLockEntries(lockfileGraph, graphAnalysis);
  const { matches, unverifiableRanges } = matchVulnerabilities(entries, database);
  const upgrades = suggestUpgrades(matches, entries, database);

  const now = context.now();
  const applied = applyAuditExceptions(matches, exceptions, now);
  const visibleMatchIds = new Set(applied.visibleMatches.map((match) => match.id));
  const visibleUpgrades = upgrades.filter((upgrade) => visibleMatchIds.has(upgrade.matchId));
  const filtered = applyAuditFilters(applied.visibleMatches, visibleUpgrades, input.filters);

  const diagnostics: Array<{
    readonly code: string;
    readonly level: 'warning' | 'info';
    readonly message: string;
  }> = [];
  if (lockfileGraph === undefined) {
    diagnostics.push({
      code:
        manager.lockfile === undefined
          ? 'PW_AUDIT_LOCKFILE_MISSING'
          : 'PW_LOCKFILE_MANAGER_NOT_IMPLEMENTED',
      level: 'warning',
      message:
        manager.lockfile === undefined
          ? 'No lockfile was found; the audit ran with an empty lock entry set.'
          : `${manager.name} lockfile parsing is not implemented; the audit ran with an empty lock entry set.`,
    });
  }
  if (unverifiableRanges.length > 0) {
    diagnostics.push({
      code: 'PW_AUDIT_UNVERIFIABLE_RANGES',
      level: 'info',
      message: `${unverifiableRanges.length} declared or affected range(s) cannot be confirmed by static analysis and are listed under unverifiableRanges.`,
    });
  }
  if (applied.expired.length > 0) {
    diagnostics.push({
      code: 'PW_AUDIT_EXCEPTIONS_EXPIRED',
      level: 'warning',
      message: `${applied.expired.length} review exception(s) are expired; their matches are included in the results again.`,
    });
  }

  return {
    schemaVersion: '1',
    generatedAt: now.toISOString(),
    tool: { name: 'pkgwise', version: context.toolVersion },
    project: {
      rootName: basename(root),
      manager: manager.name,
      ...(manager.lockfile === undefined ? {} : { lockfile: manager.lockfile }),
      mode: lockfileGraph === undefined ? 'manifest-only' : 'locked',
    },
    summary: {
      entryCount: entries.length,
      confirmedCount: matches.filter((match) => match.status === 'confirmed').length,
      rangeOnlyCount: matches.filter((match) => match.status === 'range-only').length,
      mitigatedCount: matches.filter((match) => match.status === 'mitigated').length,
      ignoredCount: applied.ignoredCount,
      expiredExceptionCount: applied.expired.length,
      unverifiableRangeCount: unverifiableRanges.length,
      filteredMatchCount: filtered.matches.length,
    },
    entries,
    matches: filtered.matches,
    upgrades: filtered.upgrades,
    exceptions: { active: applied.active, expired: applied.expired },
    unverifiableRanges,
    filters: {
      ...(input.filters?.component === undefined ? {} : { component: input.filters.component }),
      ...(input.filters?.path === undefined ? {} : { path: input.filters.path }),
      ...(input.filters?.fixStatus === undefined ? {} : { fixStatus: input.filters.fixStatus }),
    },
    diagnostics,
  };
}
