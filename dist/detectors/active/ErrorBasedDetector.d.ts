import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
export declare enum ErrorType {
    DATABASE_ERROR = "database-error",
    STACK_TRACE = "stack-trace",
    EXCEPTION = "exception",
    DEBUG_INFO = "debug-info",
    PATH_DISCLOSURE = "path-disclosure"
}
export declare class ErrorBasedDetector implements IActiveDetector {
    readonly name = "Error-Based Information Disclosure Detector";
    readonly description = "Detects information disclosure through error messages, stack traces, and exceptions";
    readonly version = "1.0.0";
    private injector;
    constructor();
    detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;
    private getErrorTriggeringPayloads;
    private checkPageForErrors;
    private hasStackTrace;
    private hasDatabaseError;
    private hasPathDisclosure;
    private hasDebugInfo;
    analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]>;
    validate(): Promise<boolean>;
    getPayloads(): string[];
    private createVulnerability;
    private extractErrorSnippet;
}
//# sourceMappingURL=ErrorBasedDetector.d.ts.map