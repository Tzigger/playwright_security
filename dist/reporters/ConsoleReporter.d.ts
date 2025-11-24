import { BaseReporter } from './base/IReporter';
import { ReportFormat } from '../types/enums';
import { Vulnerability } from '../types/vulnerability';
import { ScanResult } from '../types/scan-result';
export declare class ConsoleReporter extends BaseReporter {
    private spinner;
    private vulnCount;
    getFormat(): ReportFormat;
    onScanStarted(scanId: string): Promise<void>;
    onScannerStarted(scannerType: string): Promise<void>;
    onVulnerability(v: Vulnerability): Promise<void>;
    onScannerCompleted(scannerType: string): Promise<void>;
    onScanCompleted(result: ScanResult): Promise<void>;
}
//# sourceMappingURL=ConsoleReporter.d.ts.map