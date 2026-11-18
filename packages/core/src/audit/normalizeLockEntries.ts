import {
  stablePackageId,
  type DependencyGraphAnalysis,
} from '../project/lockfile/analyzeDependencyGraph.js';
import type {
  DependencyScope,
  LockfileGraphSnapshot,
  LockfilePackageRecord,
  LockfileSourceInfo,
} from '../project/lockfile/LockfileGraphSnapshot.js';
import type {
  AuditDeclaredRange,
  AuditLockEntry,
  AuditSourceInfo,
  DependencyPath,
} from '../public/ClientResults.js';

/**
 * Normalizes lockfile packages into audit entries keyed by component,
 * resolved version, and resolution source. Peer-context instances of the
 * same tarball collapse into one entry so evidence is never double counted,
 * while identical name+version pairs from different registries or locators
 * stay distinct and keep their original attribution.
 */
export function normalizeLockEntries(
  graph: LockfileGraphSnapshot,
  analysis: DependencyGraphAnalysis,
): AuditLockEntry[] {
  const reportsById = new Map(analysis.packages.map((report) => [report.id, report]));
  const groups = new Map<
    string,
    {
      readonly name: string;
      readonly version?: string;
      readonly source: AuditSourceInfo;
      readonly records: LockfilePackageRecord[];
    }
  >();

  for (const record of graph.packages) {
    const publicId = stablePackageId(graph.manager, record.id);
    if (!reportsById.has(publicId)) continue;
    const source = normalizeSource(record.source);
    const version = record.version === undefined ? undefined : stripPeerContext(record.version);
    const groupKey = [
      record.name,
      version ?? '',
      source.kind,
      source.registryHost ?? '',
      source.locator ?? '',
      source.patchHash ?? '',
    ].join('\0');
    const group = groups.get(groupKey) ?? {
      name: record.name,
      ...(version === undefined ? {} : { version }),
      source,
      records: [],
    };
    groups.set(groupKey, { ...group, records: [...group.records, record] });
  }

  const baseKeys = new Map<string, number>();
  for (const group of groups.values()) {
    const base = `${graph.manager}:${group.name}@${group.version ?? 'unknown'}`;
    baseKeys.set(base, (baseKeys.get(base) ?? 0) + 1);
  }
  const usedKeys = new Map<string, number>();

  const entries: AuditLockEntry[] = [];
  const sortedGroups = [...groups.values()].sort((left, right) =>
    groupSortKey(left).localeCompare(groupSortKey(right)),
  );
  for (const group of sortedGroups) {
    const base = `${graph.manager}:${group.name}@${group.version ?? 'unknown'}`;
    const total = baseKeys.get(base) ?? 1;
    const ordinal = (usedKeys.get(base) ?? 0) + 1;
    usedKeys.set(base, ordinal);
    const key = total === 1 ? base : `${base}#${ordinal}`;

    const reports = group.records.map((record) =>
      reportsById.get(stablePackageId(graph.manager, record.id)),
    );
    const depth = Math.min(...reports.map((report) => report?.minimumDepth ?? 1));
    const declaredRanges = collectDeclaredRanges(graph, group.records);
    const paths = new Map<string, DependencyPath>();
    const packageIds: string[] = [];
    for (const record of group.records) {
      const publicId = stablePackageId(graph.manager, record.id);
      packageIds.push(publicId);
      const report = reportsById.get(publicId);
      for (const path of report?.dependencyPaths ?? []) {
        paths.set(serializePath(path), path);
      }
    }
    entries.push({
      key,
      manager: graph.manager,
      name: group.name,
      ...(group.version === undefined ? {} : { version: group.version }),
      resolutionLevel: depth <= 1 ? 'direct' : 'transitive',
      depth,
      source: group.source,
      declaredRanges,
      dependencyPaths: [...paths.values()],
      packageIds: packageIds.sort(),
    });
  }
  return entries.sort((left, right) => left.key.localeCompare(right.key));
}

function groupSortKey(group: {
  readonly name: string;
  readonly version?: string;
  readonly source: AuditSourceInfo;
}): string {
  return [
    group.name,
    group.version ?? '',
    group.source.kind,
    group.source.registryHost ?? '',
    group.source.locator ?? '',
    group.source.patchHash ?? '',
  ].join('\0');
}

function collectDeclaredRanges(
  graph: LockfileGraphSnapshot,
  records: readonly LockfilePackageRecord[],
): AuditDeclaredRange[] {
  const recordIds = new Set(records.map((record) => record.id));
  const recordsById = new Map(graph.packages.map((record) => [record.id, record]));
  const ranges = new Map<string, AuditDeclaredRange>();
  const add = (specifier: string, declaredBy: string, scope: DependencyScope): void => {
    const key = `${specifier}\0${declaredBy}\0${scope}`;
    if (!ranges.has(key)) ranges.set(key, { specifier, declaredBy, scope });
  };

  for (const reference of graph.importer.dependencies) {
    if (reference.targetId !== undefined && recordIds.has(reference.targetId)) {
      add(reference.requested, `importer:${graph.importer.id}`, reference.scope);
    }
  }
  for (const record of graph.packages) {
    for (const reference of record.dependencies) {
      if (reference.targetId !== undefined && recordIds.has(reference.targetId)) {
        add(reference.requested, describeRecord(recordsById.get(record.id)), reference.scope);
      }
    }
  }
  return [...ranges.values()].sort((left, right) =>
    `${left.declaredBy}\0${left.specifier}\0${left.scope}`.localeCompare(
      `${right.declaredBy}\0${right.specifier}\0${right.scope}`,
    ),
  );
}

function describeRecord(record: LockfilePackageRecord | undefined): string {
  if (record === undefined) return 'unknown';
  const version = record.version === undefined ? undefined : stripPeerContext(record.version);
  return version === undefined ? record.name : `${record.name}@${version}`;
}

function normalizeSource(source: LockfileSourceInfo | undefined): AuditSourceInfo {
  return {
    kind: source?.kind ?? 'unknown',
    ...(source?.locator === undefined ? {} : { locator: source.locator }),
    ...(source?.registryHost === undefined ? {} : { registryHost: source.registryHost }),
    patched: source?.patched ?? false,
    patchConfirmed: source?.patchConfirmed ?? false,
    ...(source?.patchHash === undefined ? {} : { patchHash: source.patchHash }),
  };
}

function stripPeerContext(version: string): string {
  const parenthesis = version.indexOf('(');
  const underscore = version.indexOf('_');
  const boundary = [parenthesis, underscore].filter((index) => index >= 0).sort((a, b) => a - b)[0];
  return boundary === undefined ? version : version.slice(0, boundary);
}

function serializePath(path: DependencyPath): string {
  return path.packages.map((item) => item.id).join('\0');
}
