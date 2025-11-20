import { ScanContext } from './IScanner';
import { IDetector } from './IDetector';
import { ScanResult } from '../../types/scan-result';
import { PluginConfigSchema } from '../../types/config';
export interface IScannerPlugin {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly type: 'passive' | 'active' | 'hybrid';
    readonly author: string;
    readonly description: string;
    initialize(context: ScanContext): Promise<void>;
    execute(): Promise<ScanResult>;
    cleanup(): Promise<void>;
    getDependencies(): string[];
    getConfiguration(): PluginConfigSchema;
    validateConfig(config: unknown): boolean;
}
export interface IDetectorPlugin extends IDetector {
    readonly author: string;
    getConfiguration(): PluginConfigSchema;
    validateConfig(config: unknown): boolean;
}
export interface PluginMetadata {
    id: string;
    name: string;
    version: string;
    type: 'scanner' | 'detector' | 'reporter';
    author: string;
    description: string;
    homepage?: string;
    repository?: string;
    license?: string;
    tags?: string[];
    minEngineVersion?: string;
    dependencies?: string[];
}
export interface PluginLoadResult {
    success: boolean;
    metadata?: PluginMetadata;
    error?: string;
    instance?: IScannerPlugin | IDetectorPlugin;
}
//# sourceMappingURL=IPlugin.d.ts.map