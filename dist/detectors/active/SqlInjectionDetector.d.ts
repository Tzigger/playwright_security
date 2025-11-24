import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
export declare enum SqlInjectionTechnique {
    ERROR_BASED = "error-based",
    BOOLEAN_BASED = "boolean-based",
    TIME_BASED = "time-based",
    UNION_BASED = "union-based",
    STACKED_QUERIES = "stacked-queries"
}
export declare class SqlInjectionDetector implements IActiveDetector {
    readonly name = "SQL Injection Detector";
    readonly description = "Detects SQL injection vulnerabilities using multiple techniques";
    readonly version = "1.0.0";
    private injector;
    constructor();
    detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;
    private testErrorBased;
    private testBooleanBased;
    private testTimeBased;
    private testUnionBased;
    analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]>;
    validate(): Promise<boolean>;
    getPayloads(): string[];
    private hasSqlError;
    private createVulnerability;
}
//# sourceMappingURL=SqlInjectionDetector.d.ts.map