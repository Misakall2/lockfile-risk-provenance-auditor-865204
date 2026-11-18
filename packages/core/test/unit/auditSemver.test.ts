import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import {
  compareVersionStrings,
  maxSatisfying,
  minSatisfying,
  parseSemver,
  rangesOverlap,
  satisfiesRange,
} from '../../src/audit/semver.js';

describe('audit semver', () => {
  it('parses and compares versions including prereleases', () => {
    assert.deepEqual(parseSemver('1.2.3'), { major: 1, minor: 2, patch: 3, prerelease: [] });
    assert.deepEqual(parseSemver('v2.0.0-rc.1'), {
      major: 2,
      minor: 0,
      patch: 0,
      prerelease: ['rc', '1'],
    });
    assert.equal(parseSemver('not-a-version'), undefined);
    assert.ok(compareVersionStrings('1.10.0', '1.9.0') > 0);
    assert.ok(compareVersionStrings('1.0.0-alpha', '1.0.0') < 0);
    assert.ok(compareVersionStrings('1.0.0-alpha.1', '1.0.0-alpha') > 0);
  });

  it('evaluates caret, tilde, wildcard, and comparator ranges', () => {
    assert.equal(satisfiesRange('1.4.2', '^1.0.0'), true);
    assert.equal(satisfiesRange('2.0.0', '^1.0.0'), false);
    assert.equal(satisfiesRange('0.2.9', '^0.2.3'), true);
    assert.equal(satisfiesRange('0.3.0', '^0.2.3'), false);
    assert.equal(satisfiesRange('1.2.9', '~1.2.3'), true);
    assert.equal(satisfiesRange('1.3.0', '~1.2.3'), false);
    assert.equal(satisfiesRange('1.9.0', '1.x'), true);
    assert.equal(satisfiesRange('2.0.0', '1.x'), false);
    assert.equal(satisfiesRange('1.2.5', '1.2'), true);
    assert.equal(satisfiesRange('1.5.0', '>=1.2.0 <2.0.0'), true);
    assert.equal(satisfiesRange('2.0.0', '>=1.2.0 <2.0.0'), false);
    assert.equal(satisfiesRange('3.0.0', '^1.0.0 || >=3.0.0'), true);
    assert.equal(satisfiesRange('1.5.0', '1.0.0 - 2.0.0'), true);
    assert.equal(satisfiesRange('2.0.1', '1.0.0 - 2.0.0'), false);
    assert.equal(satisfiesRange('1.0.0', '*'), true);
  });

  it('keeps prerelease versions out of plain ranges', () => {
    assert.equal(satisfiesRange('1.2.3-beta', '^1.0.0'), false);
    assert.equal(satisfiesRange('1.2.3-beta', '>=1.2.3-beta'), true);
  });

  it('returns undefined for specifiers static analysis cannot resolve', () => {
    assert.equal(satisfiesRange('1.0.0', 'latest'), undefined);
    assert.equal(satisfiesRange('1.0.0', 'npm:other@^1.0.0'), undefined);
    assert.equal(satisfiesRange('1.0.0', 'file:../local'), undefined);
    assert.equal(satisfiesRange('1.0.0', 'workspace:*'), undefined);
    assert.equal(satisfiesRange('1.0.0', 'https://example.com/pkg.tgz'), undefined);
  });

  it('detects range overlap conservatively', () => {
    assert.equal(rangesOverlap('^1.0.0', '<1.5.0'), true);
    assert.equal(rangesOverlap('^1.0.0', '>=2.0.0'), false);
    assert.equal(rangesOverlap('1.2.3', '>=1.0.0 <2.0.0'), true);
    assert.equal(rangesOverlap('~1.2.0', '>=1.3.0 <1.4.0'), false);
    assert.equal(rangesOverlap('*', '<=0.0.1'), true);
    assert.equal(rangesOverlap('^1.0.0 || ^2.0.0', '2.3.4'), true);
    assert.equal(rangesOverlap('latest', '^1.0.0'), undefined);
    assert.equal(rangesOverlap('^1.0.0', 'file:../x'), undefined);
  });

  it('picks minimum and maximum satisfying versions', () => {
    const versions = ['1.0.0', '1.2.0', '1.9.4', '2.0.0'];
    assert.equal(minSatisfying(versions, '^1.2.0'), '1.2.0');
    assert.equal(maxSatisfying(versions, '^1.2.0'), '1.9.4');
    assert.equal(minSatisfying(versions, '^3.0.0'), undefined);
  });
});
