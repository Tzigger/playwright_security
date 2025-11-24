import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { ScanResult } from '../../types/scan-result';
export interface ActiveScannerConfig {
    maxDepth?: number;
    maxPages?: number;
    delayBetweenRequests?: number;
    followRedirects?: boolean;
    respectRobotsTxt?: boolean;
    userAgent?: string;
    skipStaticResources?: boolean;
    aggressiveness?: 'low' | 'medium' | 'high';
}
export declare class ActiveScanner extends BaseScanner {
    readonly id = "active-scanner";
    readonly name = "Active Scanner";
    readonly version = "1.0.0";
    readonly type: "active";
    readonly description = "Active scanner with payload injection and fuzzing capabilities";
    private config;
    private detectors;
    private domExplorer;
    private visitedUrls;
    private crawlQueue;
    constructor(config?: ActiveScannerConfig);
    registerDetector(detector: IActiveDetector): void;
    registerDetectors(detectors: IActiveDetector[]): void;
    protected onInitialize(): Promise<void>;
    execute(): Promise<ScanResult>;
    protected onCleanup(): Promise<void>;
    private isValidUrl;
    private delay;
    getDetectorCount(): number;
    getDetectorNames(): string[];
    getStatistics(): {
        visitedPages: number;
        queuedPages: number;
        maxDepth: number;
        detectorCount: number;
    };
}
//# sourceMappingURL=ActiveScanner.d.ts.map