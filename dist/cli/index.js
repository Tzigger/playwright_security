#!/usr/bin/env node
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const commander_1 = require("commander");
const ScanEngine_1 = require("../core/engine/ScanEngine");
const ActiveScanner_1 = require("../scanners/active/ActiveScanner");
const SqlInjectionDetector_1 = require("../detectors/active/SqlInjectionDetector");
const XssDetector_1 = require("../detectors/active/XssDetector");
const ErrorBasedDetector_1 = require("../detectors/active/ErrorBasedDetector");
const enums_1 = require("../types/enums");
const program = new commander_1.Command();
program
    .name('dast-scan')
    .description('Run a DAST scan with Playwright Security')
    .argument('<url>', 'Target URL to scan')
    .option('-o, --output <dir>', 'Output directory for reports', 'reports')
    .option('-f, --formats <list>', 'Comma-separated report formats (console,json,html,sarif)', 'console,json,html')
    .option('--headless', 'Run headless browser', true)
    .option('--parallel <n>', 'Parallel scanners', '2')
    .action(async (url, options) => {
    const formats = String(options.formats)
        .split(',')
        .map((s) => s.trim().toLowerCase())
        .map((s) => s);
    const config = {
        target: {
            url,
            authentication: { type: enums_1.AuthType.NONE },
            crawlDepth: 1,
            maxPages: 5,
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
            formats: formats,
            outputDir: options.output,
            verbosity: enums_1.VerbosityLevel.NORMAL,
        },
        advanced: {
            parallelism: parseInt(options.parallel, 10) || 2,
            logLevel: enums_1.LogLevel.INFO,
        },
    };
    const engine = new ScanEngine_1.ScanEngine();
    const active = new ActiveScanner_1.ActiveScanner();
    active.registerDetectors([
        new SqlInjectionDetector_1.SqlInjectionDetector(),
        new XssDetector_1.XssDetector(),
        new ErrorBasedDetector_1.ErrorBasedDetector(),
    ]);
    engine.registerScanner(active);
    await engine.loadConfiguration(config);
    await engine.scan();
    await engine.cleanup();
});
program.parseAsync(process.argv).catch((err) => {
    console.error(err);
    process.exit(1);
});
//# sourceMappingURL=index.js.map