import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { applyAuditExceptions } from '../../src/audit/applyAuditExceptions.js';
import { applyAuditFilters } from '../../src/audit/applyAuditFilters.js';
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
      id: 'GHSA-2000',
      aliases: ['CVE-2024-2000'],
      package: 'alpha',
      severity: 'high',
      affected: ['<1.5.0'],
      fixed: ['1.5.0'],
      knownVersions: [],
      references: [],
    },
    {
      id: 'GHSA-2001',
      aliases: [],
      package: 'beta',
      severity: 'medium',
      affected: ['<2.0.0'],
      fixed: ['2.0.0'],
      knownVersions: [],
      references: [],
    },
  ],
  renames: [],
};

function fixture() {
  const graph = parseNpmLockfile(
    JSON.stringify({
      name: 'fixture',
      lockfileVersion: 3,
      packages: {
        '': { dependencies: { alpha: '^1.0.0', wrapper: '1.0.0' } },
        'node_modules/alpha': { version: '1.2.0' },
        'node_modules/wrapper': { version: '1.0.0', dependencies: { beta: '^1.0.0' } },
        'node_modules/beta': { version: '1.0.0' },
      },
    }),
  );
  const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));
  const { matches } = matchVulnerabilities(entries, database);
  const upgrades = suggestUpgrades(matches, entries, database);
  return { entries, matches, upgrades };
}

describe('audit exceptions', () => {
  it('suppresses matches covered by an active exception with reason and expiry', () => {
    const { matches } = fixture();
    const applied = applyAuditExceptions(
      matches,
      [
        {
          advisory: 'CVE-2024-2000',
          package: 'alpha',
          reason: 'accepted by security review',
          expiresAt: '2099-01-01T00:00:00.000Z',
        },
      ],
      new Date('2026-01-01T00:00:00.000Z'),
    );

    assert.equal(applied.ignoredCount, 1);
    assert.equal(applied.visibleMatches.length, 1);
    assert.equal(applied.visibleMatches[0]?.package, 'beta');
    assert.equal(applied.active.length, 1);
    assert.equal(applied.active[0]?.matchedCount, 1);
    assert.equal(applied.active[0]?.reason, 'accepted by security review');
    assert.equal(applied.expired.length, 0);
  });

  it('lets expired exceptions re-enter the results', () => {
    const { matches } = fixture();
    const applied = applyAuditExceptions(
      matches,
      [
        {
          advisory: 'GHSA-2000',
          reason: 'temporary acceptance',
          expiresAt: '2020-01-01T00:00:00.000Z',
        },
      ],
      new Date('2026-01-01T00:00:00.000Z'),
    );

    assert.equal(applied.ignoredCount, 0);
    assert.equal(applied.visibleMatches.length, 2);
    assert.equal(applied.expired.length, 1);
    assert.equal(applied.expired[0]?.matchedCount, 1);
  });
});

describe('audit filters', () => {
  it('filters matches by component, dependency path, and fix status', () => {
    const { matches, upgrades } = fixture();

    const byComponent = applyAuditFilters(matches, upgrades, { component: 'alpha' });
    assert.equal(byComponent.matches.length, 1);
    assert.equal(byComponent.matches[0]?.entry.name, 'alpha');

    const byPath = applyAuditFilters(matches, upgrades, { path: 'wrapper' });
    assert.equal(byPath.matches.length, 1);
    assert.equal(byPath.matches[0]?.entry.name, 'beta');

    const byFixStatus = applyAuditFilters(matches, upgrades, { fixStatus: 'constrained' });
    assert.equal(byFixStatus.matches.length, 1);
    assert.equal(byFixStatus.matches[0]?.entry.name, 'beta');
    const ready = applyAuditFilters(matches, upgrades, { fixStatus: 'ready' });
    assert.equal(ready.matches.length, 1);
    assert.equal(ready.matches[0]?.entry.name, 'alpha');
    const unavailable = applyAuditFilters(matches, upgrades, { fixStatus: 'unavailable' });
    assert.equal(unavailable.matches.length, 0);
  });
});
