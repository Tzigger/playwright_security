import { BaseReporter } from './base/IReporter';
import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';
export declare class JsonReporter extends BaseReporter {
    getFormat(): ReportFormat;
    generate(result: ScanResult): Promise<void>;
}
//# sourceMappingURL=JsonReporter.d.ts.map