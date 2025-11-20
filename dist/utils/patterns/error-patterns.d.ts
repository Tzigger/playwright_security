export declare const SQL_ERROR_PATTERNS: RegExp[];
export declare const APPLICATION_ERROR_PATTERNS: RegExp[];
export declare const STACK_TRACE_PATTERNS: RegExp[];
export declare const PATH_DISCLOSURE_PATTERNS: RegExp[];
export declare const DATABASE_ERROR_PATTERNS: RegExp[];
export declare const AUTH_ERROR_PATTERNS: RegExp[];
export declare const COMMAND_INJECTION_ERROR_PATTERNS: RegExp[];
export declare const ALL_ERROR_PATTERNS: RegExp[];
export declare function containsErrorPattern(text: string): boolean;
export declare function findErrorPatterns(text: string): {
    pattern: RegExp;
    matches: string[];
}[];
export declare function categorizeError(text: string): string | null;
//# sourceMappingURL=error-patterns.d.ts.map