import { LogLevel } from '../../types/enums';
export class Logger {
    level;
    prefix;
    constructor(level = LogLevel.INFO, prefix = '') {
        this.level = level;
        this.prefix = prefix;
    }
    setLevel(level) {
        this.level = level;
    }
    getLevel() {
        return this.level;
    }
    error(message, ...args) {
        this.log(LogLevel.ERROR, message, ...args);
    }
    warn(message, ...args) {
        if (this.shouldLog(LogLevel.WARN)) {
            this.log(LogLevel.WARN, message, ...args);
        }
    }
    info(message, ...args) {
        if (this.shouldLog(LogLevel.INFO)) {
            this.log(LogLevel.INFO, message, ...args);
        }
    }
    debug(message, ...args) {
        if (this.shouldLog(LogLevel.DEBUG)) {
            this.log(LogLevel.DEBUG, message, ...args);
        }
    }
    child(prefix) {
        const childPrefix = this.prefix ? `${this.prefix}:${prefix}` : prefix;
        return new Logger(this.level, childPrefix);
    }
    log(level, message, ...args) {
        const timestamp = new Date().toISOString();
        const levelStr = level.toUpperCase().padEnd(5);
        const prefixStr = this.prefix ? `[${this.prefix}] ` : '';
        const formattedMessage = `${timestamp} ${levelStr} ${prefixStr}${message}`;
        switch (level) {
            case LogLevel.ERROR:
                console.error(formattedMessage, ...args);
                break;
            case LogLevel.WARN:
                console.warn(formattedMessage, ...args);
                break;
            default:
                console.log(formattedMessage, ...args);
        }
    }
    shouldLog(messageLevel) {
        const levels = [LogLevel.ERROR, LogLevel.WARN, LogLevel.INFO, LogLevel.DEBUG];
        const currentLevelIndex = levels.indexOf(this.level);
        const messageLevelIndex = levels.indexOf(messageLevel);
        return messageLevelIndex <= currentLevelIndex;
    }
}
export const globalLogger = new Logger(LogLevel.INFO);
export function createLogger(level = LogLevel.INFO, prefix = '') {
    return new Logger(level, prefix);
}
//# sourceMappingURL=Logger.js.map