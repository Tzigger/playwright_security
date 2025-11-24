"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VulnerabilitySeverity = void 0;
exports.runSecurityScan = runSecurityScan;
exports.assertNoVulnerabilities = assertNoVulnerabilities;
const ScanEngine_1 = require("../core/engine/ScanEngine");
const ActiveScanner_1 = require("../scanners/active/ActiveScanner");
const SqlInjectionDetector_1 = require("../detectors/active/SqlInjectionDetector");
const XssDetector_1 = require("../detectors/active/XssDetector");
const ErrorBasedDetector_1 = require("../detectors/active/ErrorBasedDetector");
const enums_1 = require("../types/enums");
Object.defineProperty(exports, "VulnerabilitySeverity", { enumerable: true, get: function () { return enums_1.VulnerabilitySeverity; } });
async function runSecurityScan(targetUrl, options = {}) {
    const config = {
        target: {
            url: targetUrl,
            authentication: { type: enums_1.AuthType.NONE },
            crawlDepth: 1,
            maxPages: options.maxPages || 5,
            timeout: 30000,
        },
        scanners: {
            passive: { enabled: false },
            active: {
                enabled: true,
                aggressiveness: enums_1.AggressivenessLevel.MEDIUM,
                submitForms: true,
            },
        },
        detectors: {
            enabled: [],
            sensitivity: 'normal',
        },
        browser: {
            type: enums_1.BrowserType.CHROMIUM,
            headless: options.headless !== false,
            timeout: 30000,
            viewport: { width: 1280, height: 800 },
        },
        reporting: {
            formats: [enums_1.ReportFormat.JSON],
            outputDir: './test-security-reports',
            verbosity: enums_1.VerbosityLevel.NORMAL,
        },
        advanced: {
            parallelism: 1,
            logLevel: enums_1.LogLevel.WARN,
        },
    };
    const engine = new ScanEngine_1.ScanEngine();
    const scanner = new ActiveScanner_1.ActiveScanner();
    const detectors = [];
    if (!options.detectors || options.detectors === 'all') {
        detectors.push(new SqlInjectionDetector_1.SqlInjectionDetector(), new XssDetector_1.XssDetector(), new ErrorBasedDetector_1.ErrorBasedDetector());
    }
    else if (options.detectors === 'sql') {
        detectors.push(new SqlInjectionDetector_1.SqlInjectionDetector());
    }
    else if (options.detectors === 'xss') {
        detectors.push(new XssDetector_1.XssDetector());
    }
    else if (options.detectors === 'errors') {
        detectors.push(new ErrorBasedDetector_1.ErrorBasedDetector());
    }
    scanner.registerDetectors(detectors);
    engine.registerScanner(scanner);
    await engine.loadConfiguration(config);
    const result = await engine.scan();
    await engine.cleanup();
    return result.vulnerabilities;
}
function assertNoVulnerabilities(vulnerabilities, maxAllowedSeverity = enums_1.VulnerabilitySeverity.INFO) {
    const severityOrder = [
        enums_1.VulnerabilitySeverity.INFO,
        enums_1.VulnerabilitySeverity.LOW,
        enums_1.VulnerabilitySeverity.MEDIUM,
        enums_1.VulnerabilitySeverity.HIGH,
        enums_1.VulnerabilitySeverity.CRITICAL,
    ];
    const maxIndex = severityOrder.indexOf(maxAllowedSeverity);
    const violations = vulnerabilities.filter(v => severityOrder.indexOf(v.severity) > maxIndex);
    if (violations.length > 0) {
        const summary = violations
            .map(v => `  - [${v.severity.toUpperCase()}] ${v.title}`)
            .join('\n');
        throw new Error(`Security vulnerabilities found above ${maxAllowedSeverity} severity:\n${summary}\n\n` +
            `Total: ${violations.length} vulnerability(ies)`);
    }
}
//# sourceMappingURL=helpers.js.map