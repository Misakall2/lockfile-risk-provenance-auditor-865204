import type { AuditFixStatusFilter, LockfileAuditReport } from '@lovlydev/pkgwise-core';
import { Command, Option } from 'commander';
import { readGlobalOptions } from '../options/readGlobalOptions.js';
import { renderAuditReport } from '../output/renderAuditReport.js';
import { renderStructuredResult } from '../output/renderStructuredResult.js';
import { writeTextOutput } from '../output/writeTextOutput.js';
import type { CommandContext } from './CommandContext.js';

const FIX_STATUSES: readonly AuditFixStatusFilter[] = [
  'ready',
  'constrained',
  'unavailable',
  'mitigated',
];

export function createAuditCommand(context: CommandContext): Command {
  return new Command('audit')
    .description('audit lockfile entries against an offline advisory database')
    .argument('[path]', 'project path', '.')
    .requiredOption('--advisories <file>', 'offline advisory database (JSON)')
    .option('--exceptions <file>', 'review exceptions with reasons and expiry (JSON)')
    .option('--component <name>', 'show only matches for a component')
    .option('--path <name>', 'show only matches whose dependency path contains a package')
    .addOption(
      new Option('--fix-status <status>', 'show only matches with a fix status').choices([
        ...FIX_STATUSES,
      ]),
    )
    .action(
      async (
        path: string,
        local: {
          advisories: string;
          exceptions?: string;
          component?: string;
          path?: string;
          fixStatus?: AuditFixStatusFilter;
        },
        command,
      ) => {
        const global = readGlobalOptions(command);
        const filters = {
          ...(local.component === undefined ? {} : { component: local.component }),
          ...(local.path === undefined ? {} : { path: local.path }),
          ...(local.fixStatus === undefined ? {} : { fixStatus: local.fixStatus }),
        };
        const report: LockfileAuditReport = await context.client.auditLockfile({
          root: global.root ?? path,
          signal: context.signal,
          advisoryDatabaseFile: local.advisories,
          ...(local.exceptions === undefined ? {} : { exceptionsFile: local.exceptions }),
          ...(Object.keys(filters).length === 0 ? {} : { filters }),
        });
        const content =
          global.format === 'terminal'
            ? renderAuditReport(report)
            : renderStructuredResult(report, global.format);
        await writeTextOutput(content, global.output, context.io);
        context.setExitCode(report.summary.confirmedCount > 0 ? 1 : 0);
      },
    );
}
