import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page } from 'playwright';
import { AttackSurface, InjectionContext } from './DomExplorer';
export declare enum InjectionStrategy {
    APPEND = "append",
    REPLACE = "replace",
    PREFIX = "prefix",
    WRAP = "wrap"
}
export declare enum PayloadEncoding {
    NONE = "none",
    URL = "url",
    HTML = "html",
    UNICODE = "unicode",
    BASE64 = "base64",
    DOUBLE_URL = "double-url"
}
export interface InjectionResult {
    payload: string;
    encoding: PayloadEncoding;
    strategy: InjectionStrategy;
    surface: AttackSurface;
    response?: {
        url: string;
        status: number;
        body: string;
        headers: Record<string, string>;
        timing: number;
    };
    error?: string;
}
export declare class PayloadInjector {
    protected logger: Logger;
    constructor(logLevel?: LogLevel);
    inject(page: Page, surface: AttackSurface, payload: string, options?: {
        encoding?: PayloadEncoding;
        strategy?: InjectionStrategy;
        submit?: boolean;
    }): Promise<InjectionResult>;
    injectMultiple(page: Page, surface: AttackSurface, payloads: string[], options?: {
        encoding?: PayloadEncoding;
        encodings?: PayloadEncoding[];
        strategy?: InjectionStrategy;
        submit?: boolean;
        delayMs?: number;
    }): Promise<InjectionResult[]>;
    protected encodePayload(payload: string, encoding: PayloadEncoding): string;
    private unicodeEncode;
    private applyStrategy;
    private injectIntoFormInput;
    private injectIntoUrlParameter;
    private injectIntoCookie;
    generateFuzzingPayloads(context: InjectionContext, count?: number): string[];
    private getSqlFuzzPayloads;
    private getXssFuzzPayloads;
    private getUrlFuzzPayloads;
    private getGenericFuzzPayloads;
    private delay;
}
//# sourceMappingURL=PayloadInjector.d.ts.map