import { Vulnerability, VulnerabilityCategory, VulnerabilitySeverity } from '../../types';
export interface IDetector {
    readonly id: string;
    readonly name: string;
    readonly version: string;
    readonly category: VulnerabilityCategory;
    readonly description: string;
    readonly enabledByDefault: boolean;
    detect(data: unknown): Promise<Vulnerability[]>;
    validate(vulnerability: Vulnerability): Promise<boolean>;
    getPatterns(): RegExp[];
    getCWEReferences(): string[];
    getOWASPReferences(): string[];
}
export declare abstract class BaseDetector implements IDetector {
    abstract readonly id: string;
    abstract readonly name: string;
    abstract readonly version: string;
    abstract readonly category: VulnerabilityCategory;
    abstract readonly description: string;
    readonly enabledByDefault: boolean;
    abstract detect(data: unknown): Promise<Vulnerability[]>;
    validate(vulnerability: Vulnerability): Promise<boolean>;
    abstract getPatterns(): RegExp[];
    getCWEReferences(): string[];
    getOWASPReferences(): string[];
    protected createVulnerability(params: {
        title: string;
        description: string;
        severity: VulnerabilitySeverity;
        evidence: unknown;
        remediation: string;
        confidence?: number;
        cwe?: string;
        owasp?: string;
        references?: string[];
    }): Vulnerability;
    protected generateId(): string;
    protected calculateConfidence(factors: number[]): number;
}
//# sourceMappingURL=IDetector.d.ts.map