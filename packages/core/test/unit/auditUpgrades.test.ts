import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import type { AuditAdvisoryDatabase } from '../../src/audit/AuditDatabase.js';
import { matchVulnerabilities } from '../../src/audit/matchVulnerabilities.js';
import { normalizeLockEntries } from '../../src/audit/normalizeLockEntries.js';
import { suggestUpgrades } from '../../src/audit/suggestUpgrades.js';
import { analyzeDependencyGraph } from '../../src/project/lockfile/analyzeDependencyGraph.js';
import { parseNpmLockfile } from '../../src/project/lockfile/parseNpmLockfile.js';

const database: AuditAdvisoryDatabase = {
  schemaVersion: 1,
  advisories: [
    {
      id: 'GHSA-1000',
      aliases: [],
      package: 'shared',
      severity: 'high',
      affected: ['<2.0.0'],
      fixed: ['2.0.0'],
      knownVersions: ['1.4.0', '2.0.0', '2.1.0'],
      references: [],
    },
  ],
  renames: [],
};

function audit(packages: Record<string, unknown>) {
  const graph = parseNpmLockfile(JSON.stringify({ name: 'fixture', lockfileVersion: 3, packages }));
  const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
  const { matches } = matchVulnerabilities(entries, database);
  return { entries, matches, upgrades: suggestUpgrades(matches, entries, database) };
}

describe('audit upgrade suggestions', () => {
  it('downgrades candidates that exceed the importer declared range', () => {
    const { upgrades } = audit({
      '': { dependencies: { shared: '^1.0.0' } },
      'node_modules/shared': { version: '1.4.0' },
    });

    assert.equal(upgrades.length, 1);
    const suggestion = upgrades[0];
    assert.equal(suggestion?.status, 'constrained');
    assert.equal(suggestion?.candidate, '2.0.0');
    assert.deepEqual(suggestion?.blockedBy, [{ dependent: 'importer:', specifier: '^1.0.0' }]);
    assert.equal(suggestion?.currentVersion, '1.4.0');
    assert.equal(suggestion?.entry.key, 'npm:shared@1.4.0');
  });

  it('confirms ready upgrades that stay inside the declared ranges', () => {
    const compatibleDatabase: AuditAdvisoryDatabase = {
      schemaVersion: 1,
      advisories: [
        {
          id: 'GHSA-1001',
          aliases: [],
          package: 'shared',
          severity: 'medium',
          affected: ['<1.4.2'],
          fixed: ['1.4.2'],
          knownVersions: ['1.4.2', '1.4.3'],
          references: [],
        },
      ],
      renames: [],
    };
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { shared: '^1.4.0' } },
          'node_modules/shared': { version: '1.4.0' },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, compatibleDatabase);
    const upgrades = suggestUpgrades(matches, entries, compatibleDatabase);

    assert.equal(upgrades.length, 1);
    assert.equal(upgrades[0]?.status, 'ready');
    assert.equal(upgrades[0]?.candidate, '1.4.2');
    assert.equal(upgrades[0]?.blockedBy.length, 0);
  });

  it('downgrades hints that would break a transitive dependent constraint', () => {
    const { upgrades } = audit({
      '': { dependencies: { wrapper: '1.0.0' } },
      'node_modules/wrapper': { version: '1.0.0', dependencies: { shared: '^1.2.0' } },
      'node_modules/shared': { version: '1.4.0' },
    });

    assert.equal(upgrades.length, 1);
    const suggestion = upgrades[0];
    assert.equal(suggestion?.status, 'constrained');
    assert.equal(suggestion?.candidate, '2.0.0');
    assert.deepEqual(suggestion?.blockedBy, [{ dependent: 'wrapper@1.0.0', specifier: '^1.2.0' }]);
    assert.match(suggestion?.summary ?? '', /conflicts with 1 locked constraint/);
  });

  it('reports unavailable when no fixed version is known', () => {
    const noFixDatabase: AuditAdvisoryDatabase = {
      schemaVersion: 1,
      advisories: [
        {
          id: 'GHSA-1002',
          aliases: [],
          package: 'shared',
          severity: 'low',
          affected: ['<99.0.0'],
          fixed: [],
          knownVersions: [],
          references: [],
        },
      ],
      renames: [],
    };
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { shared: '^1.0.0' } },
          'node_modules/shared': { version: '1.4.0' },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, noFixDatabase);
    const upgrades = suggestUpgrades(matches, entries, noFixDatabase);

    assert.equal(upgrades.length, 1);
    assert.equal(upgrades[0]?.status, 'unavailable');
    assert.equal(upgrades[0]?.candidate, undefined);
  });

  it('only suggests upgrades for confirmed matches, not range-only exposure', () => {
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { shared: '^1.0.0' } },
          'node_modules/shared': { version: '2.1.0' },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
    const { matches } = matchVulnerabilities(entries, database);
    const upgrades = suggestUpgrades(matches, entries, database);

    assert.equal(matches.length, 1);
    assert.equal(matches[0]?.status, 'range-only');
    assert.equal(upgrades.length, 0);
  });
});
