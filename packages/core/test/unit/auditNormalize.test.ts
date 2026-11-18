import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { normalizeLockEntries } from '../../src/audit/normalizeLockEntries.js';
import { analyzeDependencyGraph } from '../../src/project/lockfile/analyzeDependencyGraph.js';
import { parseNpmLockfile } from '../../src/project/lockfile/parseNpmLockfile.js';
import { parsePnpmLockfile } from '../../src/project/lockfile/parsePnpmLockfile.js';

describe('audit lock entry normalization', () => {
  it('keeps multiple locked versions of one component as separate entries', () => {
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { a: '^1.0.0', b: '^1.0.0' } },
          'node_modules/a': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/a/-/a-1.0.0.tgz',
            dependencies: { shared: '^2.0.0' },
          },
          'node_modules/a/node_modules/shared': {
            version: '2.1.0',
            resolved: 'https://registry.npmjs.org/shared/-/shared-2.1.0.tgz',
          },
          'node_modules/b': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/b/-/b-1.0.0.tgz',
            dependencies: { shared: '^1.0.0' },
          },
          'node_modules/shared': {
            version: '1.4.0',
            resolved: 'https://registry.npmjs.org/shared/-/shared-1.4.0.tgz',
          },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    const shared = entries.filter((entry) => entry.name === 'shared');
    assert.equal(shared.length, 2);
    assert.deepEqual(shared.map((entry) => entry.version).sort(), ['1.4.0', '2.1.0']);
    const nested = shared.find((entry) => entry.version === '2.1.0');
    assert.equal(nested?.resolutionLevel, 'transitive');
    assert.equal(nested?.depth, 2);
    assert.deepEqual(
      nested?.declaredRanges.map((range) => `${range.declaredBy}:${range.specifier}`),
      ['a@1.0.0:^2.0.0'],
    );
    const hoisted = shared.find((entry) => entry.version === '1.4.0');
    assert.equal(hoisted?.resolutionLevel, 'transitive');
    assert.deepEqual(
      hoisted?.declaredRanges.map((range) => `${range.declaredBy}:${range.specifier}`),
      ['b@1.0.0:^1.0.0'],
    );
  });

  it('does not merge same-name same-version entries from different sources', () => {
    const graph = parseNpmLockfile(
      JSON.stringify({
        name: 'fixture',
        lockfileVersion: 3,
        packages: {
          '': { dependencies: { a: '^1.0.0', b: '^1.0.0' } },
          'node_modules/a': { version: '1.0.0', dependencies: { lib: '^1.0.0' } },
          'node_modules/a/node_modules/lib': {
            version: '1.0.0',
            resolved: 'https://registry.npmjs.org/lib/-/lib-1.0.0.tgz',
          },
          'node_modules/b': { version: '1.0.0', dependencies: { lib: '^1.0.0' } },
          'node_modules/b/node_modules/lib': {
            version: '1.0.0',
            resolved: 'https://mirror.internal.example/lib/-/lib-1.0.0.tgz',
          },
        },
      }),
    );
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    const libs = entries.filter((entry) => entry.name === 'lib');
    assert.equal(libs.length, 2);
    assert.deepEqual(libs.map((entry) => entry.source.registryHost).sort(), [
      'mirror.internal.example',
      'registry.npmjs.org',
    ]);
    assert.notEqual(libs[0]?.key, libs[1]?.key);
    assert.ok(libs.every((entry) => entry.key.startsWith('npm:lib@1.0.0#')));
  });

  it('collapses pnpm peer-context instances of one tarball into a single entry', () => {
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      consumer-a:
        specifier: ^1.0.0
        version: 1.0.0(peer@2.0.0)
      consumer-b:
        specifier: ^1.0.0
        version: 1.0.0(peer@3.0.0)
packages:
  consumer-a@1.0.0(peer@2.0.0):
    resolution: {integrity: sha512-aaa}
  consumer-b@1.0.0(peer@3.0.0):
    resolution: {integrity: sha512-bbb}
  peer@2.0.0:
    resolution: {integrity: sha512-p2}
  peer@3.0.0:
    resolution: {integrity: sha512-p3}
  shared@5.0.0(peer@2.0.0):
    resolution: {integrity: sha512-s2}
  shared@5.0.0(peer@3.0.0):
    resolution: {integrity: sha512-s3}
snapshots:
  consumer-a@1.0.0(peer@2.0.0):
    dependencies:
      shared: 5.0.0(peer@2.0.0)
  consumer-b@1.0.0(peer@3.0.0):
    dependencies:
      shared: 5.0.0(peer@3.0.0)
  peer@2.0.0: {}
  peer@3.0.0: {}
  shared@5.0.0(peer@2.0.0): {}
  shared@5.0.0(peer@3.0.0): {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    const shared = entries.filter((entry) => entry.name === 'shared');
    assert.equal(shared.length, 1);
    assert.equal(shared[0]?.version, '5.0.0');
    assert.equal(shared[0]?.packageIds.length, 2);
    assert.deepEqual(
      shared[0]?.declaredRanges.map((range) => `${range.declaredBy}:${range.specifier}`).sort(),
      ['consumer-a@1.0.0:5.0.0(peer@2.0.0)', 'consumer-b@1.0.0:5.0.0(peer@3.0.0)'],
    );
  });

  it('keeps importer declarations with their origin on direct entries', () => {
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      direct-lib:
        specifier: ^3.1.0
        version: 3.1.4
packages:
  direct-lib@3.1.4:
    resolution: {integrity: sha512-d}
snapshots:
  direct-lib@3.1.4: {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    assert.equal(entries.length, 1);
    const entry = entries[0];
    assert.equal(entry?.key, 'pnpm:direct-lib@3.1.4');
    assert.equal(entry?.resolutionLevel, 'direct');
    assert.equal(entry?.source.kind, 'registry');
    assert.deepEqual(entry?.declaredRanges, [
      { specifier: '^3.1.0', declaredBy: 'importer:.', scope: 'runtime' },
    ]);
  });

  it('records pnpm tarball sources and confirmed patches with original attribution', () => {
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      patched-lib:
        specifier: 2.0.0
        version: 2.0.0(patch_hash=abc123)
      switched-lib:
        specifier: 1.0.0
        version: 1.0.0
patchedDependencies:
  patched-lib@2.0.0:
    hash: abc123
    path: patches/patched-lib@2.0.0.patch
packages:
  patched-lib@2.0.0(patch_hash=abc123):
    resolution: {integrity: sha512-p}
  switched-lib@1.0.0:
    resolution: {tarball: https://mirror.internal.example/switched-lib/-/switched-lib-1.0.0.tgz}
snapshots:
  patched-lib@2.0.0(patch_hash=abc123): {}
  switched-lib@1.0.0: {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    const patched = entries.find((entry) => entry.name === 'patched-lib');
    assert.equal(patched?.source.patched, true);
    assert.equal(patched?.source.patchConfirmed, true);
    assert.equal(patched?.source.patchHash, 'abc123');
    const switched = entries.find((entry) => entry.name === 'switched-lib');
    assert.equal(switched?.source.kind, 'tarball');
    assert.equal(switched?.source.registryHost, 'mirror.internal.example');
    assert.equal(
      switched?.source.locator,
      'https://mirror.internal.example/switched-lib/-/switched-lib-1.0.0.tgz',
    );
  });

  it('flags patches that the lockfile patch registry does not confirm', () => {
    const graph = parsePnpmLockfile(`
lockfileVersion: '9.0'
importers:
  .:
    dependencies:
      half-patched:
        specifier: 2.0.0
        version: 2.0.0(patch_hash=abc123)
patchedDependencies:
  half-patched@2.0.0:
    hash: different-hash
    path: patches/half-patched@2.0.0.patch
packages:
  half-patched@2.0.0(patch_hash=abc123):
    resolution: {integrity: sha512-p}
snapshots:
  half-patched@2.0.0(patch_hash=abc123): {}
`);
    const entries = normalizeLockEntries(graph, analyzeDependencyGraph(graph));

    const entry = entries.find((item) => item.name === 'half-patched');
    assert.equal(entry?.source.patched, true);
    assert.equal(entry?.source.patchConfirmed, false);
  });
});
