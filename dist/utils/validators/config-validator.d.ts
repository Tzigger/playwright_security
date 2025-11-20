import { ScanConfiguration } from '../../types/config';
export declare function validateScanConfiguration(config: Partial<ScanConfiguration>): {
    valid: boolean;
    errors: string[];
};
export declare function isValidUrl(url: string): boolean;
export declare function isValidRegex(pattern: string): boolean;
export declare function isValidPath(path: string): boolean;
export declare function isValidEmail(email: string): boolean;
export declare function isValidPort(port: number): boolean;
export declare function isValidConfidence(confidence: number): boolean;
//# sourceMappingURL=config-validator.d.ts.map