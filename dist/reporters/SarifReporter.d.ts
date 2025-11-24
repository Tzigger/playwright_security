import { BaseReporter } from './base/IReporter';
import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';
export declare class SarifReporter extends BaseReporter {
    getFormat(): ReportFormat;
    generate(result: ScanResult): Promise<void>;
    private toSarif;
    private severityToSarif;
}
//# sourceMappingURL=SarifReporter.d.ts.map