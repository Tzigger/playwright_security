import { Vulnerability } from '../types/vulnerability';
import { VulnerabilitySeverity } from '../types/enums';
export interface SecurityScanOptions {
    detectors?: 'all' | 'sql' | 'xss' | 'errors';
    maxPages?: number;
    headless?: boolean;
}
export declare function runSecurityScan(targetUrl: string, options?: SecurityScanOptions): Promise<Vulnerability[]>;
export declare function assertNoVulnerabilities(vulnerabilities: Vulnerability[], maxAllowedSeverity?: VulnerabilitySeverity): void;
export { VulnerabilitySeverity };
//# sourceMappingURL=helpers.d.ts.map