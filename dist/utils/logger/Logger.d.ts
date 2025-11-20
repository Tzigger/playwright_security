import { LogLevel } from '../../types/enums';
export declare class Logger {
    private level;
    private prefix;
    constructor(level?: LogLevel, prefix?: string);
    setLevel(level: LogLevel): void;
    getLevel(): LogLevel;
    error(message: string, ...args: unknown[]): void;
    warn(message: string, ...args: unknown[]): void;
    info(message: string, ...args: unknown[]): void;
    debug(message: string, ...args: unknown[]): void;
    child(prefix: string): Logger;
    private log;
    private shouldLog;
}
export declare const globalLogger: Logger;
export declare function createLogger(level?: LogLevel, prefix?: string): Logger;
//# sourceMappingURL=Logger.d.ts.map