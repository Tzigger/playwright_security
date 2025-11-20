import { AggregatedScanResult, ReportFormat } from '../../types';
export interface IReporter {
    readonly id: string;
    readonly name: string;
    readonly format: ReportFormat;
    readonly extension: string;
    generate(results: AggregatedScanResult, outputPath: string): Promise<void>;
    validateOutputPath(outputPath: string): Promise<boolean>;
    getDefaultFilename(scanId: string): string;
}
export declare abstract class BaseReporter implements IReporter {
    abstract readonly id: string;
    abstract readonly name: string;
    abstract readonly format: ReportFormat;
    abstract readonly extension: string;
    abstract generate(results: AggregatedScanResult, outputPath: string): Promise<void>;
    validateOutputPath(outputPath: string): Promise<boolean>;
    getDefaultFilename(scanId: string): string;
    protected writeFile(filePath: string, content: string): Promise<void>;
    protected formatTimestamp(date: Date): string;
    protected formatDuration(ms: number): string;
}
//# sourceMappingURL=IReporter.d.ts.map