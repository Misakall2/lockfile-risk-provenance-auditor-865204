import { PkgWiseError } from '../errors/PkgWiseError.js';
import type { FindingSeverity } from '../public/ClientResults.js';

export interface AuditAdvisoryRecord {
  readonly id: string;
  readonly aliases: readonly string[];
  readonly package: string;
  readonly severity: FindingSeverity;
  readonly summary?: string;
  readonly affected: readonly string[];
  readonly fixed: readonly string[];
  readonly knownVersions: readonly string[];
  readonly references: readonly string[];
}

export interface AuditPackageRename {
  readonly from: string;
  readonly to: string;
}

export interface AuditAdvisoryDatabase {
  readonly schemaVersion: 1;
  readonly advisories: readonly AuditAdvisoryRecord[];
  readonly renames: readonly AuditPackageRename[];
}

const SEVERITIES: readonly FindingSeverity[] = ['critical', 'high', 'medium', 'low', 'info'];

export function readAuditDatabase(value: unknown, origin: string): AuditAdvisoryDatabase {
  if (!isRecord(value)) {
    throw invalidDatabase(origin, 'the database must be a JSON object.');
  }
  if (value.schemaVersion !== 1) {
    throw invalidDatabase(origin, 'schemaVersion must be 1.');
  }
  if (!Array.isArray(value.advisories)) {
    throw invalidDatabase(origin, 'advisories must be an array.');
  }
  const advisories = value.advisories.map((item, index) =>
    readAdvisory(item, `${origin} advisories[${index}]`),
  );
  const renames = readRenames(value.renames, origin);
  return { schemaVersion: 1, advisories, renames };
}

function readAdvisory(value: unknown, context: string): AuditAdvisoryRecord {
  if (!isRecord(value)) throw invalidDatabase(context, 'advisory must be an object.');
  if (typeof value.id !== 'string' || value.id.length === 0) {
    throw invalidDatabase(context, 'advisory.id must be a non-empty string.');
  }
  if (typeof value.package !== 'string' || value.package.length === 0) {
    throw invalidDatabase(context, `advisory ${value.id} package must be a non-empty string.`);
  }
  if (
    typeof value.severity !== 'string' ||
    !SEVERITIES.includes(value.severity as FindingSeverity)
  ) {
    throw invalidDatabase(
      context,
      `advisory ${value.id} severity must be one of ${SEVERITIES.join(', ')}.`,
    );
  }
  if (!Array.isArray(value.affected) || value.affected.some((item) => typeof item !== 'string')) {
    throw invalidDatabase(context, `advisory ${value.id} affected must be a string array.`);
  }
  return {
    id: value.id,
    aliases: readStringArray(value.aliases, `${context} aliases`),
    package: value.package,
    severity: value.severity as FindingSeverity,
    ...(typeof value.summary === 'string' ? { summary: value.summary } : {}),
    affected: [...new Set(value.affected as string[])].sort(),
    fixed: readStringArray(value.fixed, `${context} fixed`).sort(),
    knownVersions: readStringArray(value.knownVersions, `${context} knownVersions`).sort(),
    references: readStringArray(value.references, `${context} references`),
  };
}

function readRenames(value: unknown, origin: string): AuditPackageRename[] {
  if (value === undefined) return [];
  if (!Array.isArray(value)) throw invalidDatabase(origin, 'renames must be an array.');
  const renames: AuditPackageRename[] = [];
  for (const [index, item] of value.entries()) {
    if (
      !isRecord(item) ||
      typeof item.from !== 'string' ||
      item.from.length === 0 ||
      typeof item.to !== 'string' ||
      item.to.length === 0
    ) {
      throw invalidDatabase(origin, `renames[${index}] must provide non-empty from/to strings.`);
    }
    renames.push({ from: item.from, to: item.to });
  }
  return renames.sort((left, right) =>
    `${left.from}\0${left.to}`.localeCompare(`${right.from}\0${right.to}`),
  );
}

function readStringArray(value: unknown, context: string): string[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.some((item) => typeof item !== 'string')) {
    throw invalidDatabase(context, 'expected a string array.');
  }
  return [...new Set(value as string[])].sort();
}

function invalidDatabase(origin: string, message: string): PkgWiseError {
  return new PkgWiseError({
    code: 'PW_AUDIT_DATABASE_INVALID',
    userMessage: `Invalid advisory database (${origin}): ${message}`,
    recoverable: false,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
