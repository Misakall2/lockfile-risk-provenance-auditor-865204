import { readFile } from 'node:fs/promises';
import { PkgWiseError } from '../errors/PkgWiseError.js';
import type { AuditExceptionInput } from '../public/ClientInputs.js';
import { readAuditDatabase, type AuditAdvisoryDatabase } from './AuditDatabase.js';

export async function loadAuditDatabase(
  inline: AuditAdvisoryDatabase | undefined,
  file: string | undefined,
  signal?: AbortSignal,
): Promise<AuditAdvisoryDatabase> {
  if (inline !== undefined) return readAuditDatabase(inline, 'inline input');
  if (file === undefined) {
    throw new PkgWiseError({
      code: 'PW_AUDIT_DATABASE_INVALID',
      userMessage:
        'An advisory database is required: pass advisories inline or an advisoryDatabaseFile path.',
      recoverable: false,
    });
  }
  const text = await readTextFile(file, 'PW_AUDIT_DATABASE_INVALID', signal);
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (cause) {
    throw new PkgWiseError({
      code: 'PW_AUDIT_DATABASE_INVALID',
      userMessage: `Advisory database ${file} is not valid JSON.`,
      recoverable: false,
      cause,
    });
  }
  return readAuditDatabase(value, file);
}

export async function loadAuditExceptions(
  inline: readonly AuditExceptionInput[] | undefined,
  file: string | undefined,
  signal?: AbortSignal,
): Promise<AuditExceptionInput[]> {
  const exceptions: AuditExceptionInput[] = [...(inline ?? [])];
  if (file !== undefined) {
    const text = await readTextFile(file, 'PW_AUDIT_EXCEPTIONS_INVALID', signal);
    let value: unknown;
    try {
      value = JSON.parse(text);
    } catch (cause) {
      throw new PkgWiseError({
        code: 'PW_AUDIT_EXCEPTIONS_INVALID',
        userMessage: `Audit exceptions file ${file} is not valid JSON.`,
        recoverable: false,
        cause,
      });
    }
    if (!Array.isArray(value)) {
      throw invalidExceptions(file, 'the file must contain a JSON array.');
    }
    for (const [index, item] of value.entries()) {
      exceptions.push(readException(item, `${file} [${index}]`));
    }
  }
  return exceptions;
}

function readException(value: unknown, context: string): AuditExceptionInput {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw invalidExceptions(context, 'exception must be an object.');
  }
  const record = value as Record<string, unknown>;
  if (typeof record.advisory !== 'string' || record.advisory.length === 0) {
    throw invalidExceptions(context, 'exception.advisory must be a non-empty string.');
  }
  if (typeof record.reason !== 'string' || record.reason.length === 0) {
    throw invalidExceptions(context, 'exception.reason must be a non-empty string.');
  }
  if (typeof record.expiresAt !== 'string' || !Number.isFinite(Date.parse(record.expiresAt))) {
    throw invalidExceptions(context, 'exception.expiresAt must be a valid ISO date.');
  }
  if (record.package !== undefined && typeof record.package !== 'string') {
    throw invalidExceptions(context, 'exception.package must be a string when present.');
  }
  return {
    advisory: record.advisory,
    ...(record.package === undefined ? {} : { package: record.package as string }),
    reason: record.reason,
    expiresAt: record.expiresAt,
  };
}

function invalidExceptions(context: string, message: string): PkgWiseError {
  return new PkgWiseError({
    code: 'PW_AUDIT_EXCEPTIONS_INVALID',
    userMessage: `Invalid audit exceptions (${context}): ${message}`,
    recoverable: false,
  });
}

async function readTextFile(
  path: string,
  code: 'PW_AUDIT_DATABASE_INVALID' | 'PW_AUDIT_EXCEPTIONS_INVALID',
  signal?: AbortSignal,
): Promise<string> {
  try {
    return await readFile(path, 'utf8');
  } catch (cause) {
    if (signal?.aborted === true) throw signal.reason;
    throw new PkgWiseError({
      code,
      userMessage: `Cannot read audit input file ${path}.`,
      recoverable: false,
      cause,
    });
  }
}
