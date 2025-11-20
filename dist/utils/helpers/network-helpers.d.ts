export declare function parseUrl(url: string): URL | null;
export declare function isUrlInScope(url: string, includePatterns: string[], excludePatterns: string[]): boolean;
export declare function matchesPattern(url: string, pattern: string): boolean;
export declare function isSameOrigin(url1: string, url2: string): boolean;
export declare function extractDomain(url: string): string | null;
export declare function isExternalUrl(url: string, baseUrl: string): boolean;
export declare function normalizeUrl(url: string): string;
export declare function extractQueryParams(url: string): Record<string, string>;
export declare function hasQueryParams(url: string): boolean;
export declare function buildUrl(baseUrl: string, params: Record<string, string>): string;
export declare function isJsonResponse(headers: Record<string, string>): boolean;
export declare function isHtmlResponse(headers: Record<string, string>): boolean;
export declare function isStaticResource(url: string): boolean;
//# sourceMappingURL=network-helpers.d.ts.map