import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, it } from 'node:test';
import { createPkgWise } from '../../src/public/index.js';

const LOCKFILE = `
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      web-framework:
        specifier: ^4.0.0
        version: 4.2.0
      session-store:
        specifier: ^1.0.0
        version: 1.1.0
    devDependencies:
      build-tool:
        specifier: ^2.0.0
        version: 2.3.1
packages:
  web-framework@4.2.0:
    resolution: {integrity: sha512-wf}
  session-store@1.1.0:
    resolution: {integrity: sha512-ss}
  build-tool@2.3.1:
    resolution: {integrity: sha512-bt}
  cookie-parser@0.9.0:
    resolution: {integrity: sha512-cp}
  json-safe@3.0.0(patch_hash=def456):
    resolution: {integrity: sha512-js}
patchedDependencies:
  json-safe@3.0.0:
    hash: def456
    path: patches/json-safe@3.0.0.patch
snapshots:
  web-framework@4.2.0:
    dependencies:
      cookie-parser: 0.9.0
      json-safe: 3.0.0(patch_hash=def456)
  session-store@1.1.0:
    dependencies:
      cookie-parser: 0.9.0
  build-tool@2.3.1: {}
  cookie-parser@0.9.0: {}
  json-safe@3.0.0(patch_hash=def456): {}
`;

const DATABASE = {
  schemaVersion: 1,
  advisories: [
    {
      id: 'GHSA-COOKIE',
      aliases: ['CVE-2026-1111'],
      package: 'cookie-parser',
      severity: 'high',
      summary: 'cookie parsing overflow',
      affected: ['<1.0.0'],
      fixed: ['1.0.0'],
      knownVersions: ['0.9.0', '1.0.0', '1.0.1'],
      references: ['https://example.com/GHSA-COOKIE'],
    },
    {
      id: 'GHSA-JSON',
      aliases: [],
      package: 'json-safe',
      severity: 'medium',
      affected: ['<3.0.1'],
      fixed: ['3.0.1'],
      knownVersions: ['3.0.0', '3.0.1'],
      references: [],
    },
    {
      id: 'GHSA-SESSION',
      aliases: [],
      package: 'session-store',
      severity: 'critical',
      affected: ['>=1.0.0 <1.1.5'],
      fixed: ['1.1.5'],
      knownVersions: ['1.1.0', '1.1.5'],
      references: [],
    },
  ],
  renames: [],
};

async function createFixture(): Promise<string> {
  const root = await mkdtemp(join(tmpdir(), 'pkgwise-audit-e2e-'));
  await writeFile(
    join(root, 'package.json'),
    JSON.stringify({
      name: 'audit-fixture',
      version: '1.0.0',
      packageManager: 'pnpm@11.19.0',
      dependencies: { 'web-framework': '^4.0.0', 'session-store': '^1.0.0' },
      devDependencies: { 'build-tool': '^2.0.0' },
    }),
  );
  await writeFile(join(root, 'pnpm-lock.yaml'), LOCKFILE);
  await writeFile(join(root, 'advisories.json'), JSON.stringify(DATABASE, null, 2));
  await writeFile(
    join(root, 'exceptions.json'),
    JSON.stringify([
      {
        advisory: 'GHSA-SESSION',
        package: 'session-store',
        reason: 'accepted: internal network only, upgrade scheduled',
        expiresAt: '2027-06-01T00:00:00.000Z',
      },
      {
        advisory: 'GHSA-COOKIE',
        reason: 'stale acceptance that must resurface',
        expiresAt: '2020-01-01T00:00:00.000Z',
      },
    ]),
  );
  return root;
}

describe('auditLockfile end-to-end', () => {
  it('audits an offline fixture deterministically across repeated runs', async () => {
    const root = await createFixture();
    try {
      const client = createPkgWise({
        version: '0.1.0-test',
        now: () => new Date('2026-11-19T00:00:00.000Z'),
      });
      const input = {
        root,
        advisoryDatabaseFile: join(root, 'advisories.json'),
        exceptionsFile: join(root, 'exceptions.json'),
      } as const;

      const first = await client.auditLockfile(input);
      const second = await client.auditLockfile(input);

      assert.deepEqual(first, second);
      assert.equal(first.project.manager, 'pnpm');
      assert.equal(first.project.mode, 'locked');
      assert.equal(first.generatedAt, '2026-11-19T00:00:00.000Z');

      assert.equal(first.summary.entryCount, 5);
      assert.equal(first.summary.confirmedCount, 2);
      assert.equal(first.summary.mitigatedCount, 1);
      assert.equal(first.summary.ignoredCount, 1);
      assert.equal(first.summary.expiredExceptionCount, 1);

      const visible = first.matches.map((match) => match.advisory.id).sort();
      assert.deepEqual(visible, ['GHSA-COOKIE', 'GHSA-JSON']);

      const cookie = first.matches.find((match) => match.advisory.id === 'GHSA-COOKIE');
      assert.equal(cookie?.status, 'confirmed');
      assert.equal(cookie?.entry.resolutionLevel, 'transitive');
      assert.equal(cookie?.resolvedVersion, '0.9.0');
      assert.deepEqual(
        cookie?.declaredRanges,
        ['0.9.0'],
        'cookie-parser is declared by lockfile packages with an exact specifier',
      );
      assert.ok(cookie !== undefined && cookie.dependencyPaths.length >= 1);
      assert.equal(
        cookie?.dependencyPaths.every((path) =>
          path.packages.some((item) => item.name === 'cookie-parser'),
        ),
        true,
      );

      const mitigated = first.matches.find((match) => match.advisory.id === 'GHSA-JSON');
      assert.equal(mitigated?.status, 'mitigated');
      assert.equal(mitigated?.advisory.severity, 'medium');
      assert.equal(mitigated?.advisory.effectiveSeverity, 'low');
      assert.equal(mitigated?.mitigation?.confirmed, true);

      const cookieUpgrade = first.upgrades.find((upgrade) => upgrade.matchId === cookie?.id);
      assert.equal(cookieUpgrade?.status, 'constrained');
      assert.equal(cookieUpgrade?.candidate, '1.0.0');
      assert.deepEqual(cookieUpgrade?.blockedBy.map((item) => item.dependent).sort(), [
        'session-store@1.1.0',
        'web-framework@4.2.0',
      ]);

      assert.equal(first.exceptions.active.length, 1);
      assert.equal(first.exceptions.active[0]?.advisory, 'GHSA-SESSION');
      assert.equal(
        first.exceptions.active[0]?.reason,
        'accepted: internal network only, upgrade scheduled',
      );
      assert.equal(first.exceptions.expired.length, 1);
      assert.equal(first.exceptions.expired[0]?.advisory, 'GHSA-COOKIE');
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('resurfaces expired exceptions when the clock moves past their expiry', async () => {
    const root = await createFixture();
    try {
      const client = createPkgWise({
        version: '0.1.0-test',
        now: () => new Date('2028-01-01T00:00:00.000Z'),
      });
      const report = await client.auditLockfile({
        root,
        advisoryDatabaseFile: join(root, 'advisories.json'),
        exceptionsFile: join(root, 'exceptions.json'),
      });

      assert.equal(report.summary.ignoredCount, 0);
      assert.equal(report.summary.expiredExceptionCount, 2);
      assert.equal(report.summary.confirmedCount, 2);
      assert.ok(report.matches.some((match) => match.advisory.id === 'GHSA-SESSION'));
      assert.ok(
        report.diagnostics.some((diagnostic) => diagnostic.code === 'PW_AUDIT_EXCEPTIONS_EXPIRED'),
      );
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  it('applies component, path, and fix-status filters to the exported report', async () => {
    const root = await createFixture();
    try {
      const client = createPkgWise({
        version: '0.1.0-test',
        now: () => new Date('2026-11-19T00:00:00.000Z'),
      });
      const base = {
        root,
        advisoryDatabaseFile: join(root, 'advisories.json'),
        exceptionsFile: join(root, 'exceptions.json'),
      };

      const byComponent = await client.auditLockfile({
        ...base,
        filters: { component: 'cookie-parser' },
      });
      assert.deepEqual(
        byComponent.matches.map((match) => match.entry.name),
        ['cookie-parser'],
      );
      assert.equal(byComponent.filters.component, 'cookie-parser');

      const byPath = await client.auditLockfile({ ...base, filters: { path: 'session-store' } });
      assert.deepEqual(
        byPath.matches.map((match) => match.entry.name),
        ['cookie-parser'],
      );

      const byFixStatus = await client.auditLockfile({
        ...base,
        filters: { fixStatus: 'mitigated' },
      });
      assert.deepEqual(
        byFixStatus.matches.map((match) => match.advisory.id),
        ['GHSA-JSON'],
      );
      assert.equal(byFixStatus.upgrades.length, 0);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });
});
