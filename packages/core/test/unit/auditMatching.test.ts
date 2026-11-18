import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { AuditAdvisoryDatabase } from '../../src/audit/AuditDatabase.js';
import { matchVulnerabilities } from '../../src/audit/matchVulnerabilities.js';
import { normalizeLockEntries } from '../../src/audit/normalizeLockEntries.js';
import { analyzeDependencyGraph } from '../../src/project/lockfile/analyzeDependencyGraph.js';
import { parseNpmLockfile } from '../../src/project/lockfile/parseNpmLockfile.js';
import { parsePnpmLockfile } from '../../src/project/lockfile/parsePnpmLockfile.js';

function npmEntries(packages: Record<string, unknown>) {
  const graph = parseNpmLockfile(JSON.stringify({ name: 'fixture', lockfileVersion: 3, packages }));
  return normalizeLockEntries(graph, analyzeDependencyGraph(graph));
}

const database: AuditAdvisoryDatabase = {
  schemaVersion: 1,
  advisories: [
    {
      id: 'GHSA-0001',
      aliases: ['CVE-2024-0001'],
      package: 'vuln-lib',
      severity: 'high',
      summary: 'test advisory',
      affected: ['<1.5.0'],
      fixed: ['1.5.0'],
      knownVersions: ['1.4.0', '1.5.0', '1.6.0'],
      references: ['https://example.com/advisory'],
    },
  ],
  renames: [],
};

describe('audit vulnerability matching', () => {
  it('matches on the resolved version and reports declared ranges alongside', () => {
    const entries = npmEntries({
      '': { dependencies: { 'vuln-lib': '^1.4.0' } },
      'node_modules/vuln-lib': { version: '1.4.0' },
    });
    const { matches } = matchVulnerabilities(entries, database);

    assert.equal(matches.length, 1);
    const match = matches[0];
    assert.equal(match?.status, 'confirmed');
    assert.equal(match?.matchedOn, 'resolved-version');
    assert.equal(match?.resolvedVersion, '1.4.0');
    assert.deepEqual(match?.declaredRanges, ['^1.4.0']);
    assert.equal(match?.advisory.severity, 'high');
    assert.equal(match?.advisory.effectiveSeverity, 'high');
    assert.equal(match?.evidence.length, 1);
    assert.equal(match?.evidence[0]?.advisoryId, 'GHSA-0001');
    assert.equal(match?.evidence[0]?.entryKey, match.entry.key);
  });

  it('reports range-only exposure when the resolved version is not affected', () => {
    const entries = npmEntries({
      '': { dependencies: { 'vuln-lib': '^1.4.0' } },
      'node_modules/vuln-lib': { version: '1.6.0' },
    });
    const { matches } = matchVulnerabilities(entries, database);

    assert.equal(matches.length, 1);
    const match = matches[0];
    assert.equal(match?.status, 'range-only');
    assert.equal(match?.matchedOn, 'declared-range');
    assert.equal(match?.resolvedVersion, '1.6.0');
    assert.deepEqual(match?.declaredRanges, ['^1.4.0']);
  });

  it('does not report when neither resolved nor declared versions intersect', () => {
    const entries = npmEntries({
      '': { dependencies: { 'vuln-lib': '^1.5.0' } },
      'node_modules/vuln-lib': { version: '1.6.0' },
    });
    const { matches } = matchVulnerabilities(entries, database);
    assert.equal(matches.length, 0);
  });

  it('follows package renames in both directions', () => {
    const renamedDatabase: AuditAdvisoryDatabase = {
      ...database,
      renames: [{ from: 'old-lib', to: 'vuln-lib' }],
    };
    const entries = npmEntries({
      '': { dependencies: { 'old-lib': '^1.4.0' } },
      'node_modules/old-lib': { version: '1.4.0' },
    });
    const { matches } = matchVulnerabilities(entries, renamedDatabase);

    assert.equal(matches.length, 1);
    assert.equal(matches[0]?.package, 'vuln-lib');
    assert.equal(matches[0]?.entry.name, 'old-lib');
    assert.equal(matches[0]?.renamedFrom, 'old-lib');
  });

  it('keeps same-name entries from switched registries as distinct matches', () => {
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { a: '1.0.0', b: '1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { 'vuln-lib': '1.4.0' } },
          'node_modules/a/node_modules/vuln-lib': {
            version: '1.4.0',
            resolved: 'https://registry.npmjs.org/vuln-lib/-/vuln-lib-1.4.0.tgz',
          },
          'node_modules/b': { version: '1.0.0', dependencies: { 'vuln-lib': '1.4.0' } },
          'node_modules/b/node_modules/vuln-lib': {
            version: '1.4.0',
            resolved: 'https://mirror.internal.example/vuln-lib/-/vuln-lib-1.4.0.tgz',
          },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, database);

    assert.equal(entries.filter((entry) => entry.name === 'vuln-lib').length, 2);
    assert.equal(matches.length, 2);
    assert.notEqual(matches[0]?.entry.key, matches[1]?.entry.key);
    const evidencePairs = new Set(
      matches.flatMap((match) =>
        match.evidence.map((item) => `${item.advisoryId}:${item.entryKey}`),
      ),
    );
    assert.equal(evidencePairs.size, 2);
  });

  it('downgrades severity only when the local patch is confirmed', () => {
    const pnpmDatabase: AuditAdvisoryDatabase = {
      schemaVersion: 1,
      advisories: [
        {
          id: 'GHSA-0002',
          aliases: [],
          package: 'patched-lib',
          severity: 'critical',
          affected: ['<2.0.1'],
          fixed: ['2.0.1'],
          knownVersions: [],
          references: [],
        },
      ],
      renames: [],
    };
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      patched-lib:
        specifier: 2.0.0
        version: 2.0.0(patch_hash=abc123)
patchedDependencies:
  patched-lib@2.0.0:
    hash: abc123
    path: patches/patched-lib@2.0.0.patch
packages:
  patched-lib@2.0.0(patch_hash=abc123):
    resolution: {integrity: sha512-p}
snapshots:
  patched-lib@2.0.0(patch_hash=abc123): {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, pnpmDatabase);

    assert.equal(matches.length, 1);
    assert.equal(matches[0]?.status, 'mitigated');
    assert.equal(matches[0]?.advisory.severity, 'critical');
    assert.equal(matches[0]?.advisory.effectiveSeverity, 'high');
    assert.equal(matches[0]?.mitigation?.confirmed, true);
  });

  it('retains the original risk when the patch is not confirmed', () => {
    const pnpmDatabase: AuditAdvisoryDatabase = {
      schemaVersion: 1,
      advisories: [
        {
          id: 'GHSA-0003',
          aliases: [],
          package: 'half-patched',
          severity: 'critical',
          affected: ['<2.0.1'],
          fixed: ['2.0.1'],
          knownVersions: [],
          references: [],
        },
      ],
      renames: [],
    };
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      half-patched:
        specifier: 2.0.0
        version: 2.0.0(patch_hash=abc123)
packages:
  half-patched@2.0.0(patch_hash=abc123):
    resolution: {integrity: sha512-p}
snapshots:
  half-patched@2.0.0(patch_hash=abc123): {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, pnpmDatabase);

    assert.equal(matches.length, 1);
    assert.equal(matches[0]?.status, 'confirmed');
    assert.equal(matches[0]?.advisory.effectiveSeverity, 'critical');
    assert.equal(matches[0]?.mitigation?.confirmed, false);
    assert.match(matches[0]?.mitigation?.note ?? '', /original risk retained/);
  });

  it('lists non-semver specifiers as unverifiable instead of guessing', () => {
    const entries = npmEntries({
      '': { dependencies: { 'vuln-lib': 'latest' } },
      'node_modules/vuln-lib': { version: '1.6.0' },
    });
    const { matches, unverifiableRanges } = matchVulnerabilities(entries, database);

    assert.equal(matches.length, 0);
    assert.equal(unverifiableRanges.length, 1);
    assert.equal(unverifiableRanges[0]?.specifier, 'latest');
    assert.equal(unverifiableRanges[0]?.package, 'vuln-lib');
  });
});
