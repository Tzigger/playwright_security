export declare const API_KEY_PATTERNS: RegExp[];
export declare const PASSWORD_PATTERNS: RegExp[];
export declare const EMAIL_PATTERNS: RegExp[];
export declare const PHONE_PATTERNS: RegExp[];
export declare const CREDIT_CARD_PATTERNS: RegExp[];
export declare const SSN_PATTERNS: RegExp[];
export declare const PRIVATE_KEY_PATTERNS: RegExp[];
export declare const JWT_PATTERNS: RegExp[];
export declare const DB_CONNECTION_PATTERNS: RegExp[];
export declare const INTERNAL_IP_PATTERNS: RegExp[];
export declare const ALL_SENSITIVE_PATTERNS: RegExp[];
export interface PatternMetadata {
    patterns: RegExp[];
    category: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
}
export declare const SENSITIVE_DATA_PATTERN_MAP: PatternMetadata[];
//# sourceMappingURL=sensitive-data-patterns.d.ts.map