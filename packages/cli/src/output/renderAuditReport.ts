import type { LockfileAuditReport } from '@lovlydev/pkgwise-core';

export function renderAuditReport(report: LockfileAuditReport): string {
  const lines = [
    `PkgWise ${report.tool.version} · audit · ${report.project.manager} · ${report.project.lockfile ?? 'no lockfile'}`,
    '',
    `${report.project.rootName} · ${report.summary.entryCount} locked entries`,
    `Matches: ${report.summary.confirmedCount} confirmed · ${report.summary.rangeOnlyCount} range-only · ${report.summary.mitigatedCount} mitigated · ${report.summary.ignoredCount} ignored · ${report.summary.filteredMatchCount} shown`,
    `Unverifiable ranges: ${report.summary.unverifiableRangeCount} · expired exceptions: ${report.summary.expiredExceptionCount}`,
  ];

  const upgradesByMatch = new Map(report.upgrades.map((upgrade) => [upgrade.matchId, upgrade]));
  for (const match of report.matches) {
    const upgrade = upgradesByMatch.get(match.id);
    lines.push(
      '',
      `${match.advisory.effectiveSeverity.toUpperCase()} [${match.status}] ${match.advisory.id} → ${match.entry.name}@${match.resolvedVersion ?? 'unknown'} (${match.entry.resolutionLevel})`,
      `  Entry: ${match.entry.key}${match.renamedFrom === undefined ? '' : ` · renamed from ${match.renamedFrom}`}`,
      `  Matched on ${match.matchedOn === 'resolved-version' ? `resolved version ${match.resolvedVersion ?? 'unknown'}` : `declared range(s) ${match.declaredRanges.join(', ')}`}`,
    );
    if (match.mitigation !== undefined) {
      lines.push(
        `  Mitigation: ${match.mitigation.confirmed ? 'patch confirmed' : 'patch unconfirmed'} — ${match.mitigation.note}`,
      );
    }
    if (upgrade !== undefined) {
      lines.push(
        `  Upgrade: ${upgrade.status}${upgrade.candidate === undefined ? '' : ` → ${upgrade.candidate}`} — ${upgrade.summary}`,
      );
      for (const blocker of upgrade.blockedBy) {
        lines.push(`    blocked by ${blocker.dependent} (${blocker.specifier})`);
      }
    }
  }

  if (report.exceptions.active.length > 0) {
    lines.push('', 'Active exceptions:');
    for (const exception of report.exceptions.active) {
      lines.push(
        `  ${exception.advisory}${exception.package === undefined ? '' : ` (${exception.package})`} · ${exception.matchedCount} match(es) · expires ${exception.expiresAt} — ${exception.reason}`,
      );
    }
  }
  if (report.exceptions.expired.length > 0) {
    lines.push('', 'Expired exceptions (matches visible again):');
    for (const exception of report.exceptions.expired) {
      lines.push(
        `  ${exception.advisory}${exception.package === undefined ? '' : ` (${exception.package})`} · expired ${exception.expiresAt} — ${exception.reason}`,
      );
    }
  }
  if (report.unverifiableRanges.length > 0) {
    lines.push('', 'Unverifiable ranges (static analysis cannot confirm):');
    for (const range of report.unverifiableRanges) {
      lines.push(`  ${range.package} "${range.specifier}" (${range.entryKey}) — ${range.reason}`);
    }
  }
  for (const diagnostic of report.diagnostics) {
    lines.push(`${diagnostic.level.toUpperCase()}: ${diagnostic.message}`);
  }
  return `${lines.join('\n')}\n`;
}
