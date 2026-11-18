export interface SemverParts {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  readonly prerelease: readonly string[];
}

export interface VersionBound {
  readonly version: SemverParts;
  readonly inclusive: boolean;
}

export interface RangeInterval {
  readonly lower?: VersionBound;
  readonly upper?: VersionBound;
  readonly empty?: boolean;
}

const VERSION_PATTERN =
  /^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

export function parseSemver(value: string): SemverParts | undefined {
  const match = VERSION_PATTERN.exec(value.trim());
  if (match === null) return undefined;
  const [, major, minor, patch, prerelease] = match;
  if (major === undefined) return undefined;
  return {
    major: Number(major),
    minor: minor === undefined ? 0 : Number(minor),
    patch: patch === undefined ? 0 : Number(patch),
    prerelease:
      prerelease === undefined
        ? []
        : prerelease.split('.').filter((identifier) => identifier.length > 0),
  };
}

export function isExactSemver(value: string): boolean {
  const trimmed = value.trim();
  return (
    /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(trimmed) &&
    parseSemver(trimmed) !== undefined
  );
}

export function formatSemver(parts: SemverParts): string {
  const base = `${parts.major}.${parts.minor}.${parts.patch}`;
  return parts.prerelease.length === 0 ? base : `${base}-${parts.prerelease.join('.')}`;
}

export function compareSemver(left: SemverParts, right: SemverParts): number {
  if (left.major !== right.major) return left.major - right.major;
  if (left.minor !== right.minor) return left.minor - right.minor;
  if (left.patch !== right.patch) return left.patch - right.patch;
  if (left.prerelease.length === 0 && right.prerelease.length === 0) return 0;
  if (left.prerelease.length === 0) return 1;
  if (right.prerelease.length === 0) return -1;
  const length = Math.min(left.prerelease.length, right.prerelease.length);
  for (let index = 0; index < length; index += 1) {
    const a = left.prerelease[index] as string;
    const b = right.prerelease[index] as string;
    const aNumeric = /^\d+$/.test(a);
    const bNumeric = /^\d+$/.test(b);
    if (aNumeric && bNumeric) {
      const difference = Number(a) - Number(b);
      if (difference !== 0) return difference;
      continue;
    }
    if (aNumeric) return -1;
    if (bNumeric) return 1;
    if (a !== b) return a < b ? -1 : 1;
  }
  return left.prerelease.length - right.prerelease.length;
}

export function compareVersionStrings(left: string, right: string): number {
  const a = parseSemver(left);
  const b = parseSemver(right);
  if (a === undefined || b === undefined) {
    return left.localeCompare(right, 'en', { numeric: true });
  }
  return compareSemver(a, b);
}

/**
 * Evaluates a semver range against an exact version.
 * Returns undefined when the range or version is not statically analyzable
 * (dist-tags, URLs, file/workspace references, npm aliases).
 */
export function satisfiesRange(version: string, range: string): boolean | undefined {
  const parsed = parseSemver(version);
  if (parsed === undefined) return undefined;
  const trimmed = range.trim();
  if (trimmed.length === 0 || trimmed === '*') return true;
  if (isNonSemverSpecifier(trimmed)) return undefined;
  const alternatives = trimmed.split('||').map((part) => part.trim());
  if (alternatives.some((part) => part.length === 0)) return undefined;
  const results = alternatives.map((part) => satisfiesAlternative(parsed, part));
  if (results.some((result) => result === true)) return true;
  if (results.every((result) => result === false)) return false;
  return undefined;
}

function satisfiesAlternative(version: SemverParts, alternative: string): boolean | undefined {
  const comparators = expandHyphenRange(alternative);
  if (comparators === undefined) return undefined;
  let sawPrereleaseComparator = false;
  for (const comparator of comparators) {
    const result = satisfiesComparator(version, comparator);
    if (result === undefined) return undefined;
    if (!result) return false;
    if (comparatorHasPrerelease(comparator)) sawPrereleaseComparator = true;
  }
  if (version.prerelease.length > 0 && !sawPrereleaseComparator) return false;
  return true;
}

function comparatorHasPrerelease(comparator: string): boolean {
  return comparator.includes('-');
}

function satisfiesComparator(version: SemverParts, comparator: string): boolean | undefined {
  const trimmed = comparator.trim();
  if (trimmed.length === 0 || trimmed === '*' || trimmed === 'x' || trimmed === 'X') return true;
  if (trimmed.startsWith('^') || trimmed.startsWith('~')) {
    const partial = parsePartialVersion(trimmed.slice(1));
    if (partial === undefined) return undefined;
    const lower = partial.floor;
    const upper = trimmed.startsWith('^') ? caretCeiling(partial) : tildeCeiling(partial);
    return compareSemver(version, lower) >= 0 && compareSemver(version, upper) < 0;
  }
  const operatorMatch = /^(<=|>=|<|>|=)?\s*(.+)$/.exec(trimmed);
  if (operatorMatch === null) return undefined;
  const operator = operatorMatch[1] ?? '';
  const partial = parsePartialVersion(operatorMatch[2] as string);
  if (partial === undefined) return undefined;
  if (partial.wildcard || partial.precision < 3) {
    if (operator !== '' && operator !== '=') return undefined;
    return inPartialWindow(version, partial);
  }
  const target = partial.floor;
  switch (operator) {
    case '':
    case '=':
      return compareSemver(version, target) === 0;
    case '<':
      return compareSemver(version, target) < 0;
    case '<=':
      return compareSemver(version, target) <= 0;
    case '>':
      return compareSemver(version, target) > 0;
    case '>=':
      return compareSemver(version, target) >= 0;
    default:
      return undefined;
  }
}

interface PartialVersion {
  readonly floor: SemverParts;
  readonly ceiling: SemverParts;
  readonly wildcard: boolean;
  readonly precision: 1 | 2 | 3;
}

function parsePartialVersion(value: string): PartialVersion | undefined {
  const trimmed = value.trim();
  const prereleaseIndex = trimmed.indexOf('-');
  const buildIndex = trimmed.indexOf('+');
  const coreEnd = [prereleaseIndex, buildIndex].filter((index) => index >= 0).sort((a, b) => a - b);
  const core = trimmed.slice(0, coreEnd[0] ?? trimmed.length).replace(/^v/, '');
  const prerelease =
    prereleaseIndex >= 0
      ? trimmed
          .slice(prereleaseIndex + 1, buildIndex >= 0 ? buildIndex : trimmed.length)
          .split('.')
          .filter((identifier) => identifier.length > 0)
      : [];
  const segments = core.split('.');
  if (segments.length > 3 || segments.some((segment) => segment.length === 0)) return undefined;
  const wildcardIndex = segments.findIndex((segment) => /^(?:x|X|\*)$/.test(segment));
  if (
    wildcardIndex >= 0 &&
    segments.slice(wildcardIndex).some((segment) => !/^(?:x|X|\*)$/.test(segment))
  ) {
    return undefined;
  }
  const effective = wildcardIndex >= 0 ? segments.slice(0, wildcardIndex) : segments;
  if (effective.some((segment) => !/^\d+$/.test(segment))) return undefined;
  const numbers = effective.map((segment) => Number(segment));
  const precision = (wildcardIndex >= 0 ? effective.length : segments.length) as 1 | 2 | 3;
  if (precision < 1 || precision > 3) return undefined;
  const [major = 0, minor = 0, patch = 0] = numbers;
  const floor: SemverParts = { major, minor, patch, prerelease };
  const ceiling: SemverParts =
    precision === 1
      ? { major: major + 1, minor: 0, patch: 0, prerelease: [] }
      : precision === 2
        ? { major, minor: minor + 1, patch: 0, prerelease: [] }
        : { major, minor, patch: patch + 1, prerelease: [] };
  return { floor, ceiling, wildcard: wildcardIndex >= 0, precision };
}

function inPartialWindow(version: SemverParts, partial: PartialVersion): boolean {
  return compareSemver(version, partial.floor) >= 0 && compareSemver(version, partial.ceiling) < 0;
}

function caretCeiling(partial: PartialVersion): SemverParts {
  const { major, minor, patch } = partial.floor;
  if (partial.precision === 1) return { major: major + 1, minor: 0, patch: 0, prerelease: [] };
  if (partial.precision === 2) {
    return major === 0
      ? { major: 0, minor: minor + 1, patch: 0, prerelease: [] }
      : { major: major + 1, minor: 0, patch: 0, prerelease: [] };
  }
  if (major > 0) return { major: major + 1, minor: 0, patch: 0, prerelease: [] };
  if (minor > 0) return { major: 0, minor: minor + 1, patch: 0, prerelease: [] };
  return { major: 0, minor: 0, patch: patch + 1, prerelease: [] };
}

function tildeCeiling(partial: PartialVersion): SemverParts {
  const { major, minor } = partial.floor;
  if (partial.precision === 1) return { major: major + 1, minor: 0, patch: 0, prerelease: [] };
  return { major, minor: minor + 1, patch: 0, prerelease: [] };
}

function expandHyphenRange(alternative: string): string[] | undefined {
  const hyphen = /\s+-\s+/.exec(alternative);
  if (hyphen === null) return alternative.split(/\s+/).filter((part) => part.length > 0);
  const from = alternative.slice(0, hyphen.index).trim();
  const to = alternative.slice(hyphen.index + hyphen[0].length).trim();
  const lower = parsePartialVersion(from);
  const upper = parsePartialVersion(to);
  if (lower === undefined || upper === undefined) return undefined;
  const comparators = [`>=${formatSemver(lower.floor)}`];
  comparators.push(
    upper.wildcard ? `<${formatSemver(upper.ceiling)}` : `<=${formatSemver(upper.floor)}`,
  );
  return comparators;
}

function isNonSemverSpecifier(specifier: string): boolean {
  if (/^(?:file|link|workspace|git|git\+|https?|npm|portal|patch|jsr):/.test(specifier)) {
    return true;
  }
  // Bare dist-tags such as "latest" or "beta" carry no static version meaning.
  return /^[A-Za-z][0-9A-Za-z.-]*$/.test(specifier) && !/^v?\d/.test(specifier);
}

/**
 * Computes conservative interval bounds for each ||-alternative of a range.
 * Returns undefined when any alternative cannot be bounded statically.
 */
export function rangeIntervals(range: string): RangeInterval[] | undefined {
  const trimmed = range.trim();
  if (trimmed.length === 0 || trimmed === '*') return [{}];
  if (isNonSemverSpecifier(trimmed)) return undefined;
  const alternatives = trimmed.split('||').map((part) => part.trim());
  if (alternatives.some((part) => part.length === 0)) return undefined;
  const intervals: RangeInterval[] = [];
  for (const alternative of alternatives) {
    const interval = alternativeInterval(alternative);
    if (interval === undefined) return undefined;
    intervals.push(interval);
  }
  return intervals;
}

function alternativeInterval(alternative: string): RangeInterval | undefined {
  const comparators = expandHyphenRange(alternative);
  if (comparators === undefined) return undefined;
  let interval: RangeInterval = {};
  for (const comparator of comparators) {
    const next = comparatorInterval(comparator.trim());
    if (next === undefined) return undefined;
    const merged = intersectIntervals(interval, next);
    if (merged === undefined) return undefined;
    interval = merged;
  }
  return interval;
}

function comparatorInterval(comparator: string): RangeInterval | undefined {
  if (comparator.length === 0 || comparator === '*' || comparator === 'x' || comparator === 'X') {
    return {};
  }
  if (comparator.startsWith('^') || comparator.startsWith('~')) {
    const partial = parsePartialVersion(comparator.slice(1));
    if (partial === undefined || partial.floor.prerelease.length > 0) return undefined;
    const ceiling = comparator.startsWith('^') ? caretCeiling(partial) : tildeCeiling(partial);
    return {
      lower: { version: partial.floor, inclusive: true },
      upper: { version: ceiling, inclusive: false },
    };
  }
  const operatorMatch = /^(<=|>=|<|>|=)?\s*(.+)$/.exec(comparator);
  if (operatorMatch === null) return undefined;
  const operator = operatorMatch[1] ?? '';
  const partial = parsePartialVersion(operatorMatch[2] as string);
  if (partial === undefined || partial.floor.prerelease.length > 0) return undefined;
  if (partial.wildcard || partial.precision < 3) {
    if (operator !== '' && operator !== '=') return undefined;
    return {
      lower: { version: partial.floor, inclusive: true },
      upper: { version: partial.ceiling, inclusive: false },
    };
  }
  const target = partial.floor;
  switch (operator) {
    case '':
    case '=':
      return {
        lower: { version: target, inclusive: true },
        upper: { version: target, inclusive: true },
      };
    case '<':
      return { upper: { version: target, inclusive: false } };
    case '<=':
      return { upper: { version: target, inclusive: true } };
    case '>':
      return { lower: { version: target, inclusive: false } };
    case '>=':
      return { lower: { version: target, inclusive: true } };
    default:
      return undefined;
  }
}

function intersectIntervals(left: RangeInterval, right: RangeInterval): RangeInterval | undefined {
  if (left.empty === true || right.empty === true) return { empty: true };
  const lower = maxBound(left.lower, right.lower);
  const upper = minBound(left.upper, right.upper);
  if (lower !== undefined && upper !== undefined) {
    const order = compareSemver(lower.version, upper.version);
    if (order > 0 || (order === 0 && (!lower.inclusive || !upper.inclusive))) {
      return { empty: true };
    }
  }
  return { ...(lower === undefined ? {} : { lower }), ...(upper === undefined ? {} : { upper }) };
}

function maxBound(
  left: VersionBound | undefined,
  right: VersionBound | undefined,
): VersionBound | undefined {
  if (left === undefined) return right;
  if (right === undefined) return left;
  const order = compareSemver(left.version, right.version);
  if (order !== 0) return order > 0 ? left : right;
  return left.inclusive ? right : left;
}

function minBound(
  left: VersionBound | undefined,
  right: VersionBound | undefined,
): VersionBound | undefined {
  if (left === undefined) return right;
  if (right === undefined) return left;
  const order = compareSemver(left.version, right.version);
  if (order !== 0) return order < 0 ? left : right;
  return left.inclusive ? right : left;
}

/**
 * Conservative overlap test between two ranges. Returns undefined when either
 * range cannot be bounded statically; otherwise answers whether some version
 * could satisfy both. Interval-based, so it may over-approximate (never
 * under-approximates) for exotic comparator mixes.
 */
export function rangesOverlap(left: string, right: string): boolean | undefined {
  const leftIntervals = rangeIntervals(left);
  const rightIntervals = rangeIntervals(right);
  if (leftIntervals === undefined || rightIntervals === undefined) return undefined;
  for (const a of leftIntervals) {
    for (const b of rightIntervals) {
      if (intervalsOverlap(a, b)) return true;
    }
  }
  return false;
}

function intervalsOverlap(left: RangeInterval, right: RangeInterval): boolean {
  if (left.empty === true || right.empty === true) return false;
  if (left.upper !== undefined && right.lower !== undefined) {
    const order = compareSemver(left.upper.version, right.lower.version);
    if (order < 0 || (order === 0 && (!left.upper.inclusive || !right.lower.inclusive))) {
      return false;
    }
  }
  if (right.upper !== undefined && left.lower !== undefined) {
    const order = compareSemver(right.upper.version, left.lower.version);
    if (order < 0 || (order === 0 && (!right.upper.inclusive || !left.lower.inclusive))) {
      return false;
    }
  }
  return true;
}

export function minSatisfying(versions: readonly string[], range: string): string | undefined {
  return pickSatisfying(versions, range, 'ascending');
}

export function maxSatisfying(versions: readonly string[], range: string): string | undefined {
  return pickSatisfying(versions, range, 'descending');
}

function pickSatisfying(
  versions: readonly string[],
  range: string,
  direction: 'ascending' | 'descending',
): string | undefined {
  const sorted = [...versions].sort(compareVersionStrings);
  if (direction === 'descending') sorted.reverse();
  for (const candidate of sorted) {
    if (satisfiesRange(candidate, range) === true) return candidate;
  }
  return undefined;
}
