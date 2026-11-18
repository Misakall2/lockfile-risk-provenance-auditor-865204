# Lockfile risk audit

`pkgwise audit` (core API: `auditLockfile`) audits locked dependencies against an
**offline advisory database**. It never merges distinct locked instances by name
alone: entries are normalized by component, resolved version, resolution source,
and resolution level, and every matched vulnerability keeps a deduplicated
evidence chain back to the exact lock entries it hit.

## Running

```sh
pkgwise audit . --advisories advisories.json [--exceptions exceptions.json] \
  [--component <name>] [--path <name>] [--fix-status ready|constrained|unavailable|mitigated]
```

Use `--format json` for the machine-readable report. The exit code is `1` when
any confirmed (unignored, unmitigated) vulnerability is present, `0` otherwise.

## Advisory database format

```json
{
  "schemaVersion": 1,
  "advisories": [
    {
      "id": "GHSA-xxxx",
      "aliases": ["CVE-2026-0001"],
      "package": "cookie-parser",
      "severity": "high",
      "summary": "…",
      "affected": ["<1.0.0"],
      "fixed": ["1.0.0"],
      "knownVersions": ["0.9.0", "1.0.0"],
      "references": ["https://example.com/advisory"]
    }
  ],
  "renames": [{ "from": "old-name", "to": "new-name" }]
}
```

- `affected` ranges are matched against the **resolved** locked version first;
  a resolved hit is a `confirmed` match.
- Declared ranges (importer specifiers and dependent constraints) are checked
  for overlap independently. If only a declared range intersects, the match is
  reported as `range-only` with both the declared range and the actual resolved
  version in the report.
- `renames` are followed in both directions, so an advisory published under a
  new package name still matches lock entries using the old name (and vice
  versa); the match records `renamedFrom`.
- `fixed` and `knownVersions` feed upgrade suggestions; offline audits cannot
  invent versions, so keep `knownVersions` current.

## Normalization and provenance

- npm (`package-lock.json`) and pnpm (`pnpm-lock.yaml`) lockfiles are parsed by
  separate parsers; manager-specific fields (`resolved` vs `resolution`,
  `patchedDependencies`) are never mixed.
- Source provenance (`registry`/`tarball`/`git`/`file`/`link`/`unknown`,
  registry host, original locator) is preserved per entry. The same
  `name@version` locked from two different registries produces **two** entries
  with distinct keys (`npm:lib@1.0.0#1`, `#2`), so evidence is never merged or
  double counted.
- pnpm peer-context instances of the same tarball collapse into one entry
  (they are the same artifact) while keeping every dependency path.
- pnpm patches: an entry carrying `(patch_hash=…)` is only treated as mitigated
  when the lockfile's `patchedDependencies` registry declares the same
  `name@version` with a matching hash. A confirmed patch downgrades the
  effective severity by one step and marks the match `mitigated`; an
  unconfirmed patch leaves the original risk untouched and says so in
  `mitigation.note`.

## Upgrade suggestions

Each confirmed match gets a suggestion anchored to the locked entry (never a
bare version number):

- `ready` — the smallest non-affected candidate above the current version that
  satisfies **every** complementary constraint (importer specifier plus all
  dependent ranges).
- `constrained` — a fixing candidate exists but violates at least one locked
  constraint; the blocking dependents and specifiers are listed in
  `blockedBy`, and the hint is downgraded rather than presented as safe.
- `unavailable` — no fixed version is known to the offline database.

## Exceptions (accepted risks)

```json
[
  {
    "advisory": "GHSA-xxxx",
    "package": "optional-name",
    "reason": "accepted by security review 2026-11",
    "expiresAt": "2027-06-01T00:00:00.000Z"
  }
]
```

Active exceptions (matched by advisory id or alias, optionally scoped to a
package) suppress matches and are exported with their reason and expiry.
Expired exceptions **re-enter the scan results** automatically and are listed
under `exceptions.expired` with a `PW_AUDIT_EXCEPTIONS_EXPIRED` diagnostic.

## Filters

The exported report can be filtered by `component` (entry or advisory package
name), `path` (any package name along the dependency path), and `fixStatus`
(`ready` / `constrained` / `unavailable` / `mitigated`). Applied filters are
echoed under `filters`, and `summary.filteredMatchCount` reports the
post-filter count while the other summary counters stay global.

## What static analysis cannot confirm

The following are reported under `unverifiableRanges` instead of being
guessed:

- **Non-semver specifiers**: dist-tags (`latest`), `file:`, `link:`,
  `workspace:`, `git:`/URL dependencies, `npm:` aliases, `portal:`/`patch:`
  protocols. Their semantic content is not statically decidable.
- **Prerelease ranges** in interval arithmetic: bounds for ranges containing
  prerelease comparators are not computed, so overlap is reported as
  unverifiable.
- **Local overrides without a patch registry**: `file:`/`link:` sources and
  pnpm patches whose hash is absent from `patchedDependencies` cannot be
  confirmed effective, so the original risk is retained.
- **Exotic comparator mixes**: range overlap is interval-based and
  conservative — it may report overlap where a perfect solver would find none,
  but it never reports disjoint ranges as overlapping.

## Determinism

Given the same lockfile, database, exceptions, and clock, repeated runs produce
byte-identical reports (entry keys, match fingerprints, and evidence ids are
stable hashes; all collections are sorted). The end-to-end fixture test runs
the audit twice and asserts deep equality.
