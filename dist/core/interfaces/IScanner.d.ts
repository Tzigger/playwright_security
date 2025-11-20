import { Page, BrowserContext } from '@playwright/test';
import { ScanConfiguration } from '../../types/config';
import { ScanResult } from '../../types/scan-result';
import { Logger } from '../../utils/logger/Logger';
export interface ScanContext {
    page: Page;
    browserContext: BrowserContext;
    config: ScanConfiguration;
    logger: Logger;
    emitVulnerability?: (vulnerability: unknown) => void;
    metadata?: Record<string, unknown>;
}
export interface IScanner {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly type: 'passive' | 'active' | 'hybrid';
    readonly description: string;
    initialize(context: ScanContext): Promise<void>;
    execute(): Promise<ScanResult>;
    cleanup(): Promise<void>;
    isEnabled(config: ScanConfiguration): boolean;
    getDependencies(): string[];
    validateConfig(config: ScanConfiguration): boolean;
}
export declare abstract class BaseScanner implements IScanner {
    abstract readonly id: string;
    abstract readonly name: string;
    abstract readonly version: string;
    abstract readonly type: 'passive' | 'active' | 'hybrid';
    abstract readonly description: string;
    protected context?: ScanContext;
    protected startTime?: Date;
    initialize(context: ScanContext): Promise<void>;
    abstract execute(): Promise<ScanResult>;
    cleanup(): Promise<void>;
    isEnabled(config: ScanConfiguration): boolean;
    getDependencies(): string[];
    validateConfig(_config: ScanConfiguration): boolean;
    protected onInitialize(): Promise<void>;
    protected onCleanup(): Promise<void>;
    protected getContext(): ScanContext;
}
//# sourceMappingURL=IScanner.d.ts.map