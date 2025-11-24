"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ScanEngine = void 0;
const enums_1 = require("../../types/enums");
const Logger_1 = require("../../utils/logger/Logger");
const BrowserManager_1 = require("../browser/BrowserManager");
const ConfigurationManager_1 = require("../config/ConfigurationManager");
const events_1 = require("events");
const uuid_1 = require("uuid");
const enums_2 = require("../../types/enums");
const ConsoleReporter_1 = require("../../reporters/ConsoleReporter");
const JsonReporter_1 = require("../../reporters/JsonReporter");
const HtmlReporter_1 = require("../../reporters/HtmlReporter");
const SarifReporter_1 = require("../../reporters/SarifReporter");
class ScanEngine extends events_1.EventEmitter {
    logger;
    browserManager;
    configManager;
    scanners = new Map();
    vulnerabilities = [];
    scanId = null;
    scanStatus = enums_1.ScanStatus.PENDING;
    startTime = 0;
    endTime = 0;
    reporters = [];
    constructor() {
        super();
        this.logger = new Logger_1.Logger(enums_1.LogLevel.INFO, 'ScanEngine');
        this.browserManager = BrowserManager_1.BrowserManager.getInstance();
        this.configManager = ConfigurationManager_1.ConfigurationManager.getInstance();
    }
    registerScanner(scanner) {
        this.scanners.set(scanner.type, scanner);
        this.logger.info(`Registered scanner: ${scanner.type}`);
    }
    registerScanners(scanners) {
        scanners.forEach((scanner) => this.registerScanner(scanner));
    }
    registerReporter(reporter) {
        this.reporters.push(reporter);
    }
    registerReporters(reporters) {
        reporters.forEach((r) => this.registerReporter(r));
    }
    async loadConfiguration(config) {
        this.logger.info('Loading scan configuration');
        this.configManager.loadFromObject(config);
    }
    async loadConfigurationFromFile(filePath) {
        this.logger.info(`Loading scan configuration from file: ${filePath}`);
        await this.configManager.loadFromFile(filePath);
    }
    async scan() {
        this.logger.info('Starting DAST scan');
        if (!this.configManager.hasConfig()) {
            throw new Error('No configuration loaded. Call loadConfiguration() first.');
        }
        if (this.scanners.size === 0) {
            throw new Error('No scanners registered. Register at least one scanner.');
        }
        const config = this.configManager.getConfig();
        this.scanId = (0, uuid_1.v4)();
        this.scanStatus = enums_1.ScanStatus.RUNNING;
        this.startTime = Date.now();
        this.vulnerabilities = [];
        this.emit('scanStarted', { scanId: this.scanId, config });
        await this.initializeReporters(config);
        await Promise.all(this.reporters.map((r) => r.onScanStarted(this.scanId, config)));
        let browserContext = null;
        let page = null;
        try {
            this.logger.info('Initializing browser');
            await this.browserManager.initialize(config.browser);
            browserContext = await this.browserManager.createContext(this.scanId);
            page = await this.browserManager.createPage(this.scanId);
            const scanContext = {
                page,
                browserContext,
                config,
                logger: this.logger.child('Scanner'),
                emitVulnerability: (vuln) => this.handleVulnerability(vuln),
            };
            const enabledScanners = Array.from(this.scanners.entries()).filter(([_, s]) => s.isEnabled(config));
            const parallelism = Math.max(1, config.advanced?.parallelism || 1);
            const runScanner = async (type, scanner) => {
                try {
                    this.logger.info(`Running scanner: ${type}`);
                    this.emit('scannerStarted', { scannerType: type });
                    await Promise.all(this.reporters.map((r) => r.onScannerStarted(String(type))));
                    const subContextId = `${this.scanId}-${String(type)}`;
                    const subBrowserContext = await this.browserManager.createContext(subContextId);
                    const subPage = await this.browserManager.createPage(subContextId);
                    const ctx = {
                        ...scanContext,
                        page: subPage,
                        browserContext: subBrowserContext,
                        emitVulnerability: (v) => this.handleVulnerability(v),
                    };
                    await scanner.initialize(ctx);
                    await scanner.execute();
                    await scanner.cleanup();
                    await this.browserManager.closeContext(subContextId);
                    this.emit('scannerCompleted', { scannerType: type });
                    await Promise.all(this.reporters.map((r) => r.onScannerCompleted(String(type))));
                }
                catch (error) {
                    this.logger.error(`Scanner ${type} failed: ${error}`);
                    this.emit('scannerFailed', { scannerType: type, error });
                }
            };
            if (parallelism > 1 && enabledScanners.length > 1) {
                await Promise.all(enabledScanners.map(([type, scanner]) => runScanner(type, scanner)));
            }
            else {
                for (const [type, scanner] of enabledScanners) {
                    await runScanner(type, scanner);
                }
            }
            this.scanStatus = enums_1.ScanStatus.COMPLETED;
            this.endTime = Date.now();
            this.logger.info(`Scan completed. Found ${this.vulnerabilities.length} vulnerabilities in ${this.endTime - this.startTime}ms`);
        }
        catch (error) {
            this.scanStatus = enums_1.ScanStatus.FAILED;
            this.endTime = Date.now();
            this.logger.error(`Scan failed: ${error}`);
            this.emit('scanFailed', { error });
            throw error;
        }
        finally {
            if (this.scanId) {
                await this.browserManager.closeContext(this.scanId);
            }
        }
        const result = this.generateScanResult();
        this.emit('scanCompleted', result);
        await Promise.all(this.reporters.map((r) => r.onScanCompleted(result)));
        await Promise.all(this.reporters.map((r) => r.generate(result)));
        return result;
    }
    handleVulnerability(vulnerability) {
        this.vulnerabilities.push(vulnerability);
        this.logger.info(`Vulnerability detected: [${vulnerability.severity}] ${vulnerability.title}`);
        this.emit('vulnerabilityDetected', vulnerability);
        void Promise.all(this.reporters.map((r) => r.onVulnerability(vulnerability)));
    }
    generateScanResult() {
        const config = this.configManager.getConfig();
        const summary = {
            total: this.vulnerabilities.length,
            critical: this.vulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.CRITICAL)
                .length,
            high: this.vulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.HIGH).length,
            medium: this.vulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.MEDIUM)
                .length,
            low: this.vulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.LOW).length,
            info: this.vulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.INFO).length,
        };
        return {
            scanId: this.scanId,
            targetUrl: config.target.url,
            status: this.scanStatus,
            startTime: this.startTime,
            endTime: this.endTime,
            duration: this.endTime - this.startTime,
            vulnerabilities: this.vulnerabilities,
            summary,
            config,
        };
    }
    async stop() {
        this.logger.warn('Stopping scan');
        this.scanStatus = enums_1.ScanStatus.FAILED;
        this.endTime = Date.now();
        if (this.scanId) {
            await this.browserManager.closeContext(this.scanId);
        }
        this.emit('scanStopped');
    }
    async cleanup() {
        this.logger.info('Cleaning up ScanEngine');
        try {
            await this.browserManager.cleanup();
            this.scanners.clear();
            this.reporters = [];
            this.vulnerabilities = [];
            this.scanId = null;
            this.scanStatus = enums_1.ScanStatus.PENDING;
        }
        catch (error) {
            this.logger.error(`Cleanup failed: ${error}`);
            throw error;
        }
    }
    getVulnerabilities() {
        return [...this.vulnerabilities];
    }
    getStatus() {
        return this.scanStatus;
    }
    getScannerCount() {
        return this.scanners.size;
    }
    hasScanner(type) {
        return this.scanners.has(type);
    }
    getRegisteredScanners() {
        return Array.from(this.scanners.keys());
    }
    async initializeReporters(config) {
        if (this.reporters.length > 0)
            return;
        const formats = config.reporting?.formats || [enums_2.ReportFormat.CONSOLE];
        const options = {
            outputDir: config.reporting?.outputDir || 'reports',
            verbosity: config.reporting?.verbosity || 'normal',
            includeScreenshots: config.reporting?.includeScreenshots || false,
            fileNameTemplate: config.reporting?.fileNameTemplate,
            openInBrowser: config.reporting?.openInBrowser || false,
        };
        const created = [];
        for (const f of formats) {
            if (f === enums_2.ReportFormat.CONSOLE)
                created.push(new ConsoleReporter_1.ConsoleReporter());
            if (f === enums_2.ReportFormat.JSON)
                created.push(new JsonReporter_1.JsonReporter());
            if (f === enums_2.ReportFormat.HTML)
                created.push(new HtmlReporter_1.HtmlReporter());
            if (f === enums_2.ReportFormat.SARIF)
                created.push(new SarifReporter_1.SarifReporter());
        }
        const byFmt = new Map();
        for (const r of created)
            byFmt.set(r.getFormat(), r);
        this.reporters = Array.from(byFmt.values());
        await Promise.all(this.reporters.map((r) => r.init(config, options)));
    }
}
exports.ScanEngine = ScanEngine;
//# sourceMappingURL=ScanEngine.js.map