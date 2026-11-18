import type {
  AnalyzeProjectInput,
  AuditLockfileInput,
  CacheStatusInput,
  ClearCacheInput,
  ComparePackagesInput,
  DiagnoseInput,
  ExplainFindingInput,
  InspectPackageInput,
} from './ClientInputs.js';
import type {
  AnalysisReport,
  CacheStatusReport,
  ClearCacheResult,
  DoctorReport,
  FindingExplanation,
  LockfileAuditReport,
  PackageComparison,
  PackageInspection,
} from './ClientResults.js';

export interface PkgWiseClient {
  analyzeProject(input: AnalyzeProjectInput): Promise<AnalysisReport>;
  auditLockfile(input: AuditLockfileInput): Promise<LockfileAuditReport>;
  inspectPackage(input: InspectPackageInput): Promise<PackageInspection>;
  comparePackages(input: ComparePackagesInput): Promise<PackageComparison>;
  explainFinding(input: ExplainFindingInput): Promise<FindingExplanation>;
  diagnose(input: DiagnoseInput): Promise<DoctorReport>;
  getCacheStatus(input?: CacheStatusInput): Promise<CacheStatusReport>;
  clearCache(input?: ClearCacheInput): Promise<ClearCacheResult>;
}
