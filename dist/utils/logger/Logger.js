"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.globalLogger = exports.Logger = void 0;
exports.createLogger = createLogger;
const enums_1 = require("../../types/enums");
class Logger {
    level;
    prefix;
    constructor(level = enums_1.LogLevel.INFO, prefix = '') {
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
        this.log(enums_1.LogLevel.ERROR, message, ...args);
    }
    warn(message, ...args) {
        if (this.shouldLog(enums_1.LogLevel.WARN)) {
            this.log(enums_1.LogLevel.WARN, message, ...args);
        }
    }
    info(message, ...args) {
        if (this.shouldLog(enums_1.LogLevel.INFO)) {
            this.log(enums_1.LogLevel.INFO, message, ...args);
        }
    }
    debug(message, ...args) {
        if (this.shouldLog(enums_1.LogLevel.DEBUG)) {
            this.log(enums_1.LogLevel.DEBUG, message, ...args);
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
            case enums_1.LogLevel.ERROR:
                console.error(formattedMessage, ...args);
                break;
            case enums_1.LogLevel.WARN:
                console.warn(formattedMessage, ...args);
                break;
            default:
                console.log(formattedMessage, ...args);
        }
    }
    shouldLog(messageLevel) {
        const levels = [enums_1.LogLevel.ERROR, enums_1.LogLevel.WARN, enums_1.LogLevel.INFO, enums_1.LogLevel.DEBUG];
        const currentLevelIndex = levels.indexOf(this.level);
        const messageLevelIndex = levels.indexOf(messageLevel);
        return messageLevelIndex <= currentLevelIndex;
    }
}
exports.Logger = Logger;
exports.globalLogger = new Logger(enums_1.LogLevel.INFO);
function createLogger(level = enums_1.LogLevel.INFO, prefix = '') {
    return new Logger(level, prefix);
}
//# sourceMappingURL=Logger.js.map