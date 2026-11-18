import { parse } from 'yaml';
import { PkgWiseError } from '../../errors/PkgWiseError.js';
import type {
  DependencyScope,
  LockfileDependencyReference,
  LockfileGraphSnapshot,
  LockfilePackageRecord,
  LockfileSourceInfo,
} from './LockfileGraphSnapshot.js';
import { isRecord, lockfileParseError } from './lockfileUtilities.js';

export function parsePnpmLockfile(
  text: string,
  importerIds: readonly string[] = ['.'],
): LockfileGraphSnapshot {
  let value: unknown;
  try {
    value = parse(text, { maxAliasCount: 50, strict: true });
  } catch (cause) {
    throw lockfileParseError('pnpm-lock.yaml is not valid YAML.', cause);
  }
  if (!isRecord(value)) throw lockfileParseError('pnpm-lock.yaml must contain an object.');

  const lockfileVersion = normalizeLockfileVersion(value.lockfileVersion);
  const major = Number.parseInt(lockfileVersion.split('.')[0] ?? '', 10);
  if (!Number.isInteger(major) || major < 6 || major > 9) {
    throw new PkgWiseError({
      code: 'PW_LOCKFILE_VERSION_UNSUPPORTED',
      userMessage: `pnpm lockfileVersion ${lockfileVersion} is unsupported; expected schema family 6 through 9.`,
      recoverable: false,
    });
  }

  const packageData = isRecord(value.packages) ? value.packages : {};
  const snapshotData = isRecord(value.snapshots) ? value.snapshots : packageData;
  const identities = createIdentityIndex(packageData, snapshotData);
  const declaredPatches = readDeclaredPatches(value.patchedDependencies);
  const packages: LockfilePackageRecord[] = [];

  for (const key of [
    ...new Set([...Object.keys(packageData), ...Object.keys(snapshotData)]),
  ].sort()) {
    const metadata = packageData[key];
    const snapshot = snapshotData[key];
    if (metadata !== undefined && !isRecord(metadata)) {
      throw lockfileParseError(`pnpm package ${key} must be an object.`);
    }
    if (snapshot !== undefined && !isRecord(snapshot)) {
      throw lockfileParseError(`pnpm snapshot ${key} must be an object.`);
    }
    const identity = parsePnpmPackageKey(key);
    if (identity === undefined) continue;
    const relations = isRecord(snapshot) ? snapshot : isRecord(metadata) ? metadata : {};
    const resolution =
      isRecord(metadata) && isRecord(metadata.resolution) ? metadata.resolution : {};
    packages.push({
      id: key,
      name: identity.name,
      version: identity.version,
      integrity: typeof resolution.integrity === 'string' ? 'present' : 'missing',
      source: readPnpmSource(resolution, identity, declaredPatches),
      dependencies: readPnpmDependencySections(relations, (name, requested) =>
        resolvePnpmTarget(name, requested, identities),
      ),
    });
  }

  const importers = value.importers;
  if (!isRecord(importers) || !isRecord(importers['.'])) {
    throw lockfileParseError('pnpm-lock.yaml importers must contain the root importer ".".');
  }
  const selectedImporters = [...new Set(importerIds)].sort();
  const importerDependencies = selectedImporters.flatMap((importerId) => {
    const importer = importers[importerId];
    if (!isRecord(importer)) {
      throw lockfileParseError(
        `pnpm-lock.yaml does not contain selected workspace importer ${JSON.stringify(importerId)}.`,
      );
    }
    return readPnpmImporter(importer, identities);
  });

  return {
    manager: 'pnpm',
    lockfileVersion,
    fidelity: 'full',
    packages,
    importer: {
      id: selectedImporters.join(','),
      dependencies: deduplicateReferences(importerDependencies),
    },
  };
}

function readDeclaredPatches(value: unknown): ReadonlyMap<string, string> {
  const patches = new Map<string, string>();
  if (!isRecord(value)) return patches;
  for (const [specifier, entry] of Object.entries(value).sort(([a], [b]) => a.localeCompare(b))) {
    if (isRecord(entry) && typeof entry.hash === 'string') {
      patches.set(specifier, entry.hash);
    }
  }
  return patches;
}

function readPnpmSource(
  resolution: Record<string, unknown>,
  identity: { readonly name: string; readonly version: string },
  declaredPatches: ReadonlyMap<string, string>,
): LockfileSourceInfo {
  const patchHash = /\(patch_hash=([^)]+)\)/.exec(identity.version)?.[1];
  const baseVersion = stripPeerSuffix(identity.version).replace(/\(patch_hash=[^)]+\)/g, '');
  const declaredHash =
    declaredPatches.get(`${identity.name}@${baseVersion}`) ?? declaredPatches.get(identity.version);
  const patch =
    patchHash === undefined
      ? {}
      : {
          patched: true,
          patchHash,
          patchConfirmed: declaredHash !== undefined && declaredHash === patchHash,
        };
  if (typeof resolution.tarball === 'string') {
    const tarball = resolution.tarball;
    const host = URL.canParse(tarball) ? new URL(tarball).host : undefined;
    return {
      kind: 'tarball',
      locator: tarball,
      ...(host === undefined ? {} : { registryHost: host }),
      ...patch,
    };
  }
  if (typeof resolution.repo === 'string' || resolution.type === 'git') {
    return {
      kind: 'git',
      ...(typeof resolution.repo === 'string' ? { locator: resolution.repo } : {}),
      ...patch,
    };
  }
  if (resolution.type === 'directory' || typeof resolution.directory === 'string') {
    return {
      kind: 'file',
      ...(typeof resolution.directory === 'string' ? { locator: resolution.directory } : {}),
      ...patch,
    };
  }
  if (typeof resolution.integrity === 'string') {
    return { kind: 'registry', ...patch };
  }
  return { kind: 'unknown', ...patch };
}

function deduplicateReferences(
  references: readonly LockfileDependencyReference[],
): LockfileDependencyReference[] {
  return [
    ...new Map(
      references.map((reference) => [
        `${reference.name}\0${reference.scope}\0${reference.targetId ?? ''}\0${reference.requested}`,
        reference,
      ]),
    ).values(),
  ].sort((left, right) =>
    `${left.name}\0${left.scope}\0${left.targetId ?? ''}`.localeCompare(
      `${right.name}\0${right.scope}\0${right.targetId ?? ''}`,
    ),
  );
}

function readPnpmImporter(
  importer: Record<string, unknown>,
  identities: ReadonlyMap<string, string>,
): LockfileDependencyReference[] {
  return readPnpmSections(importer, identities, true);
}

function readPnpmDependencySections(
  record: Record<string, unknown>,
  resolveTarget: (name: string, requested: string) => string | undefined,
): LockfileDependencyReference[] {
  return readSections(record, resolveTarget, false);
}

function readPnpmSections(
  record: Record<string, unknown>,
  identities: ReadonlyMap<string, string>,
  importer: boolean,
): LockfileDependencyReference[] {
  return readSections(
    record,
    (name, requested) => resolvePnpmTarget(name, requested, identities),
    importer,
  );
}

function readSections(
  record: Record<string, unknown>,
  resolveTarget: (name: string, requested: string) => string | undefined,
  importer: boolean,
): LockfileDependencyReference[] {
  const sections: ReadonlyArray<readonly [string, DependencyScope, boolean, boolean]> = [
    ['dependencies', 'runtime', false, false],
    ['devDependencies', 'development', false, false],
    ['optionalDependencies', 'optional', true, false],
    ['peerDependencies', 'peer', false, true],
  ];
  const references: LockfileDependencyReference[] = [];
  const optionalSection = record.optionalDependencies;
  const optionalNames = new Set(isRecord(optionalSection) ? Object.keys(optionalSection) : []);
  for (const [field, scope, optional, peer] of sections) {
    const section = record[field];
    if (section === undefined) continue;
    if (!isRecord(section)) throw lockfileParseError(`pnpm ${field} must be an object.`);
    for (const [name, raw] of Object.entries(section).sort(([a], [b]) => a.localeCompare(b))) {
      if (scope === 'runtime' && optionalNames.has(name)) continue;
      const reference = readPnpmReference(raw, importer, field, name);
      const targetId = resolveTarget(name, reference.resolution);
      references.push({
        name,
        requested: reference.requested,
        scope,
        optional,
        peer,
        ...(targetId === undefined ? {} : { targetId }),
      });
    }
  }
  return references;
}

function readPnpmReference(
  raw: unknown,
  importer: boolean,
  field: string,
  name: string,
): { readonly requested: string; readonly resolution: string } {
  if (typeof raw === 'string') return { requested: raw, resolution: raw };
  if (importer && isRecord(raw) && typeof raw.version === 'string') {
    // pnpm importers record both the declared specifier and the resolved
    // version; keep them distinct so range matching uses the declaration
    // while graph resolution follows the locked version.
    const requested = typeof raw.specifier === 'string' ? raw.specifier : raw.version;
    return { requested, resolution: raw.version };
  }
  throw lockfileParseError(`pnpm ${field}.${name} must provide a string version.`);
}

function createIdentityIndex(
  packages: Record<string, unknown>,
  snapshots: Record<string, unknown>,
): Map<string, string> {
  const result = new Map<string, string>();
  for (const key of [...new Set([...Object.keys(packages), ...Object.keys(snapshots)])].sort()) {
    const identity = parsePnpmPackageKey(key);
    if (identity === undefined) continue;
    result.set(`${identity.name}\0${identity.version}`, key);
    result.set(`${identity.name}\0${stripPeerSuffix(identity.version)}`, key);
  }
  return result;
}

function resolvePnpmTarget(
  name: string,
  reference: string,
  identities: ReadonlyMap<string, string>,
): string | undefined {
  if (/^(?:link|workspace|file|git|https?):/.test(reference)) return undefined;
  const alias = reference.startsWith('npm:') ? parseNpmAlias(reference.slice(4)) : undefined;
  const targetName = alias?.name ?? name;
  const normalized = alias?.version ?? reference;
  return (
    identities.get(`${targetName}\0${normalized}`) ??
    identities.get(`${targetName}\0${stripPeerSuffix(normalized)}`)
  );
}

function parsePnpmPackageKey(
  key: string,
): { readonly name: string; readonly version: string } | undefined {
  const normalized = key.startsWith('/') ? key.slice(1) : key;
  if (key.startsWith('/')) {
    const parts = normalized.split('/');
    if (parts[0]?.startsWith('@')) {
      if (parts.length < 3) return undefined;
      return { name: `${parts[0]}/${parts[1]}`, version: parts.slice(2).join('/') };
    }
    if (parts.length < 2) return undefined;
    return { name: parts[0] ?? '', version: parts.slice(1).join('/') };
  }
  const delimiter = normalized.startsWith('@')
    ? normalized.indexOf('@', normalized.indexOf('/') + 1)
    : normalized.indexOf('@');
  if (delimiter <= 0) return undefined;
  return { name: normalized.slice(0, delimiter), version: normalized.slice(delimiter + 1) };
}

function parseNpmAlias(
  value: string,
): { readonly name: string; readonly version: string } | undefined {
  const delimiter = value.startsWith('@')
    ? value.indexOf('@', value.indexOf('/') + 1)
    : value.indexOf('@');
  if (delimiter <= 0) return undefined;
  return { name: value.slice(0, delimiter), version: value.slice(delimiter + 1) };
}

function stripPeerSuffix(version: string): string {
  const index = version.indexOf('(');
  return index < 0 ? version : version.slice(0, index);
}

function normalizeLockfileVersion(value: unknown): string {
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value === 'string' && value.length > 0) return value;
  throw lockfileParseError('pnpm-lock.yaml lockfileVersion is missing or invalid.');
}
