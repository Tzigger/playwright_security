"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConsoleReporter = void 0;
const tslib_1 = require("tslib");
const chalk_1 = tslib_1.__importDefault(require("chalk"));
const ora_1 = tslib_1.__importDefault(require("ora"));
const IReporter_1 = require("./base/IReporter");
const enums_1 = require("../types/enums");
class ConsoleReporter extends IReporter_1.BaseReporter {
    spinner = (0, ora_1.default)({ spinner: 'dots' });
    vulnCount = 0;
    getFormat() {
        return enums_1.ReportFormat.CONSOLE;
    }
    async onScanStarted(scanId) {
        this.spinner.start(`Starting scan ${scanId} on ${this.config.target.url}`);
    }
    async onScannerStarted(scannerType) {
        this.spinner.text = `Running scanner: ${scannerType}`;
    }
    async onVulnerability(v) {
        this.vulnCount += 1;
        const sev = v.severity.toUpperCase();
        const sevColor = v.severity === 'critical' ? chalk_1.default.bgRed.white :
            v.severity === 'high' ? chalk_1.default.red :
                v.severity === 'medium' ? chalk_1.default.yellow :
                    v.severity === 'low' ? chalk_1.default.blue : chalk_1.default.gray;
        this.spinner.stop();
        console.log(`${sevColor(` ${sev} `)} ${chalk_1.default.bold(v.title)} ${chalk_1.default.gray(`(${v.category})`)}`);
        this.spinner.start();
    }
    async onScannerCompleted(scannerType) {
        this.spinner.text = `Completed: ${scannerType}`;
    }
    async onScanCompleted(result) {
        this.spinner.stop();
        const s = result.summary;
        console.log(chalk_1.default.bold(`\nScan complete in ${result.duration}ms: `) +
            `${s.total} vulns (C:${s.critical} H:${s.high} M:${s.medium} L:${s.low} I:${s.info})\n`);
    }
}
exports.ConsoleReporter = ConsoleReporter;
//# sourceMappingURL=ConsoleReporter.js.map