import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
export declare enum XssType {
    REFLECTED = "reflected",
    STORED = "stored",
    DOM_BASED = "dom-based"
}
export declare class XssDetector implements IActiveDetector {
    readonly name = "XSS Detector";
    readonly description = "Detects Cross-Site Scripting (XSS) vulnerabilities with context-aware payloads";
    readonly version = "1.0.0";
    private injector;
    constructor();
    detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;
    private testReflectedXss;
    private testStoredXss;
    private testDomBasedXss;
    private getContextAwarePayloads;
    private isPayloadExecuted;
    private checkDialogPresence;
    analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]>;
    validate(): Promise<boolean>;
    getPayloads(): string[];
    private createVulnerability;
}
//# sourceMappingURL=XssDetector.d.ts.map