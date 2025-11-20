export declare function generateUUID(): string;
export declare function generateShortId(): string;
export declare function hashString(str: string): string;
export declare function encodeBase64(str: string): string;
export declare function decodeBase64(str: string): string;
export declare function sanitizeFilename(filename: string): string;
export declare function truncate(str: string, maxLength: number): string;
export declare function deepClone<T>(obj: T): T;
export declare function sleep(ms: number): Promise<void>;
export declare function retry<T>(fn: () => Promise<T>, maxRetries?: number, delayMs?: number): Promise<T>;
export declare function formatBytes(bytes: number): string;
export declare function isEmpty(obj: unknown): boolean;
//# sourceMappingURL=common-helpers.d.ts.map