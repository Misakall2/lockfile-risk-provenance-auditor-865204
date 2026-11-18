import { createHash } from 'node:crypto';
import type {
  AuditEvidenceItem,
  AuditLockEntry,
  AuditUnverifiableRange,
  AuditVulnerabilityMatch,
  FindingSeverity,
} from '../public/ClientResults.js';
import type { AuditAdvisoryDatabase, AuditAdvisoryRecord } from './AuditDatabase.js';
import { rangesOverlap, satisfiesRange } from './semver.js';

export interface VulnerabilityMatchResult {
  readonly matches: readonly AuditVulnerabilityMatch[];
  readonly unverifiableRanges: readonly AuditUnverifiableRange[];
}

const SEVERITY_ORDER: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * Matches advisories against normalized entries using both the resolved
 * version and every declared range that selected the entry. Package renames
 * are followed in both directions; a confirmed local patch downgrades the
 * effective severity, while an unconfirmed patch leaves the risk unchanged.
 */
export function matchVulnerabilities(
  entries: readonly AuditLockEntry[],
  database: AuditAdvisoryDatabase,
): VulnerabilityMatchResult {
  const renames = buildRenameIndex(database);
  const unverifiable = new Map<string, AuditUnverifiableRange>();
  const matches: AuditVulnerabilityMatch[] = [];

  for (const entry of entries) {
    const names = candidateNames(entry.name, renames);
    for (const advisory of database.advisories) {
      if (!names.has(advisory.package)) continue;
      const renamedFrom = advisory.package === entry.name ? undefined : entry.name;
      const resolved = resolveMatch(entry, advisory, unverifiable);
      const declared = declaredMatches(entry, advisory, unverifiable);
      if (resolved !== true && declared.length === 0) continue;

      const baseStatus = resolved === true ? 'confirmed' : 'range-only';
      const patched = entry.source.patched;
      const patchConfirmed = patched && entry.source.patchConfirmed;
      const status = patchConfirmed ? 'mitigated' : baseStatus;
      const effectiveSeverity = patchConfirmed
        ? downgradeSeverity(advisory.severity)
        : advisory.severity;
      const id = matchFingerprint(advisory.id, entry.key);
      const evidence: AuditEvidenceItem[] = [
        {
          id: createHash('sha256').update(`audit-evidence\0${id}`).digest('hex'),
          advisoryId: advisory.id,
          entryKey: entry.key,
          summary:
            resolved === true
              ? `${advisory.id} matches resolved version ${entry.version ?? 'unknown'} of ${entry.name} (entry ${entry.key}).`
              : `${advisory.id} overlaps declared range(s) ${declared.join(', ')} for ${entry.name}; resolved version ${entry.version ?? 'unknown'} is not affected.`,
        },
      ];
      matches.push({
        id,
        advisory: {
          id: advisory.id,
          aliases: advisory.aliases,
          severity: advisory.severity,
          effectiveSeverity,
          ...(advisory.summary === undefined ? {} : { summary: advisory.summary }),
          references: advisory.references,
        },
        package: advisory.package,
        entry: {
          key: entry.key,
          name: entry.name,
          ...(entry.version === undefined ? {} : { version: entry.version }),
          resolutionLevel: entry.resolutionLevel,
        },
        status,
        matchedOn: resolved === true ? 'resolved-version' : 'declared-range',
        declaredRanges: declared,
        ...(entry.version === undefined ? {} : { resolvedVersion: entry.version }),
        ...(renamedFrom === undefined ? {} : { renamedFrom }),
        ...(patched
          ? {
              mitigation: {
                kind: 'patch' as const,
                confirmed: patchConfirmed,
                note: patchConfirmed
                  ? 'Local patch is declared in the lockfile and its hash matches; severity downgraded.'
                  : 'Local patch is applied but not confirmed by the lockfile patch registry; original risk retained.',
              },
            }
          : {}),
        dependencyPaths: entry.dependencyPaths,
        evidence,
      });
    }
  }

  matches.sort(
    (left, right) =>
      SEVERITY_ORDER.indexOf(left.advisory.effectiveSeverity) -
        SEVERITY_ORDER.indexOf(right.advisory.effectiveSeverity) ||
      left.advisory.id.localeCompare(right.advisory.id) ||
      left.entry.key.localeCompare(right.entry.key),
  );
  return {
    matches,
    unverifiableRanges: [...unverifiable.values()].sort((left, right) =>
      `${left.entryKey}\0${left.specifier}`.localeCompare(`${right.entryKey}\0${right.specifier}`),
    ),
  };
}

function resolveMatch(
  entry: AuditLockEntry,
  advisory: AuditAdvisoryRecord,
  unverifiable: Map<string, AuditUnverifiableRange>,
): boolean | undefined {
  if (entry.version === undefined) return undefined;
  let sawUnknown = false;
  for (const range of advisory.affected) {
    const result = satisfiesRange(entry.version, range);
    if (result === true) return true;
    if (result === undefined) sawUnknown = true;
  }
  if (sawUnknown) {
    noteUnverifiable(
      unverifiable,
      entry,
      advisory.affected.join(' || '),
      `affected range for ${advisory.id} is not statically analyzable against the resolved version`,
    );
    return undefined;
  }
  return false;
}

function declaredMatches(
  entry: AuditLockEntry,
  advisory: AuditAdvisoryRecord,
  unverifiable: Map<string, AuditUnverifiableRange>,
): string[] {
  const matched = new Set<string>();
  for (const declared of entry.declaredRanges) {
    let sawUnknown = false;
    for (const affected of advisory.affected) {
      const overlap = rangesOverlap(declared.specifier, affected);
      if (overlap === true) {
        matched.add(declared.specifier);
        break;
      }
      if (overlap === undefined) sawUnknown = true;
    }
    if (sawUnknown && !matched.has(declared.specifier)) {
      noteUnverifiable(
        unverifiable,
        entry,
        declared.specifier,
        'declared range cannot be compared statically against the advisory range',
      );
    }
  }
  return [...matched].sort();
}

function noteUnverifiable(
  unverifiable: Map<string, AuditUnverifiableRange>,
  entry: AuditLockEntry,
  specifier: string,
  reason: string,
): void {
  const key = `${entry.key}\0${specifier}\0${reason}`;
  if (unverifiable.has(key)) return;
  unverifiable.set(key, {
    entryKey: entry.key,
    package: entry.name,
    specifier,
    reason,
  });
}

function downgradeSeverity(severity: FindingSeverity): FindingSeverity {
  const index = SEVERITY_ORDER.indexOf(severity);
  return SEVERITY_ORDER[Math.min(index + 1, SEVERITY_ORDER.length - 1)] as FindingSeverity;
}

function matchFingerprint(advisoryId: string, entryKey: string): string {
  return createHash('sha256').update(`audit-match\0${advisoryId}\0${entryKey}`).digest('hex');
}

function buildRenameIndex(database: AuditAdvisoryDatabase): Map<string, Set<string>> {
  const index = new Map<string, Set<string>>();
  for (const rename of database.renames) {
    const fromSet = index.get(rename.from) ?? new Set<string>();
    fromSet.add(rename.to);
    index.set(rename.from, fromSet);
    const toSet = index.get(rename.to) ?? new Set<string>();
    toSet.add(rename.from);
    index.set(rename.to, toSet);
  }
  return index;
}

function candidateNames(
  name: string,
  renames: ReadonlyMap<string, ReadonlySet<string>>,
): Set<string> {
  return new Set([name, ...(renames.get(name) ?? [])]);
}
