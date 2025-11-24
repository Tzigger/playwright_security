"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseReporter = void 0;
class BaseReporter {
    config;
    options;
    async init(config, options) {
        this.config = config;
        this.options = options;
    }
    async onScanStarted(_scanId, _config) { }
    async onScannerStarted(_scannerType) { }
    async onVulnerability(_vuln) { }
    async onScannerCompleted(_scannerType) { }
    async onScanCompleted(_result) { }
    async generate(_result) { }
}
exports.BaseReporter = BaseReporter;
//# sourceMappingURL=IReporter.js.map