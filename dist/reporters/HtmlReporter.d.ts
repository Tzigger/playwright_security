import { BaseReporter } from './base/IReporter';
import { ReportFormat } from '../types/enums';
import { ScanResult } from '../types/scan-result';
export declare class HtmlReporter extends BaseReporter {
    private template?;
    getFormat(): ReportFormat;
    init(config: any, options: any): Promise<void>;
    generate(result: ScanResult): Promise<void>;
}
//# sourceMappingURL=HtmlReporter.d.ts.map