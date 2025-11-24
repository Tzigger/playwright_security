"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ActiveScanner = void 0;
const IScanner_1 = require("../../core/interfaces/IScanner");
const enums_1 = require("../../types/enums");
const DomExplorer_1 = require("./DomExplorer");
class ActiveScanner extends IScanner_1.BaseScanner {
    id = 'active-scanner';
    name = 'Active Scanner';
    version = '1.0.0';
    type = 'active';
    description = 'Active scanner with payload injection and fuzzing capabilities';
    config;
    detectors = new Map();
    domExplorer;
    visitedUrls = new Set();
    crawlQueue = [];
    constructor(config = {}) {
        super();
        this.config = {
            maxDepth: config.maxDepth || 3,
            maxPages: config.maxPages || 20,
            delayBetweenRequests: config.delayBetweenRequests || 500,
            followRedirects: config.followRedirects !== false,
            respectRobotsTxt: config.respectRobotsTxt !== false,
            skipStaticResources: config.skipStaticResources !== false,
            aggressiveness: config.aggressiveness || 'medium',
            ...config,
        };
        this.domExplorer = new DomExplorer_1.DomExplorer(enums_1.LogLevel.INFO);
    }
    registerDetector(detector) {
        this.detectors.set(detector.name, detector);
        this.context?.logger.info(`Registered active detector: ${detector.name}`);
    }
    registerDetectors(detectors) {
        detectors.forEach((detector) => this.registerDetector(detector));
    }
    async onInitialize() {
        const context = this.getContext();
        context.logger.info('Initializing ActiveScanner');
        this.visitedUrls.clear();
        this.crawlQueue = [];
        for (const [name, detector] of this.detectors) {
            const isValid = await detector.validate();
            if (!isValid) {
                context.logger.warn(`Detector ${name} validation failed`);
            }
        }
        context.logger.info('ActiveScanner initialized successfully');
    }
    async execute() {
        const context = this.getContext();
        const { page, config } = context;
        const targetUrl = config.target.url;
        context.logger.info(`Starting active scan on: ${targetUrl}`);
        const allVulnerabilities = [];
        try {
            this.crawlQueue.push(targetUrl);
            let depth = 0;
            while (this.crawlQueue.length > 0 && depth < this.config.maxDepth) {
                const url = this.crawlQueue.shift();
                if (this.visitedUrls.has(url) || this.visitedUrls.size >= this.config.maxPages) {
                    continue;
                }
                context.logger.info(`Scanning page [${this.visitedUrls.size + 1}/${this.config.maxPages}]: ${url}`);
                try {
                    await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
                    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => { });
                }
                catch (error) {
                    context.logger.warn(`Failed to navigate to ${url}: ${error}`);
                    continue;
                }
                this.visitedUrls.add(url);
                const allSurfaces = await this.domExplorer.explore(page);
                const supportedTypes = [DomExplorer_1.AttackSurfaceType.FORM_INPUT, DomExplorer_1.AttackSurfaceType.URL_PARAMETER, DomExplorer_1.AttackSurfaceType.COOKIE];
                const attackSurfaces = allSurfaces.filter(s => supportedTypes.includes(s.type));
                context.logger.info(`Found ${attackSurfaces.length} supported attack surfaces on ${url}`);
                for (const [name, detector] of this.detectors) {
                    context.logger.info(`Running detector: ${name}`);
                    try {
                        const vulns = await detector.detect({
                            page,
                            attackSurfaces,
                            baseUrl: url,
                        });
                        if (vulns.length > 0) {
                            context.logger.info(`Detector ${name} found ${vulns.length} vulnerabilities`);
                            allVulnerabilities.push(...vulns);
                            vulns.forEach(vuln => context.emitVulnerability?.(vuln));
                        }
                    }
                    catch (error) {
                        context.logger.error(`Detector ${name} failed: ${error}`);
                    }
                    await this.delay(this.config.delayBetweenRequests);
                }
                const links = attackSurfaces.filter(s => s.type === DomExplorer_1.AttackSurfaceType.LINK);
                for (const link of links) {
                    if (link.value && !this.visitedUrls.has(link.value) && this.isValidUrl(link.value, targetUrl)) {
                        this.crawlQueue.push(link.value);
                    }
                }
                depth++;
                await this.delay(this.config.delayBetweenRequests);
            }
            context.logger.info(`Active scan completed. Found ${allVulnerabilities.length} vulnerabilities`);
        }
        catch (error) {
            context.logger.error(`Active scan failed: ${error}`);
        }
        const endTime = new Date();
        const duration = endTime.getTime() - this.startTime.getTime();
        const summary = {
            total: allVulnerabilities.length,
            critical: allVulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.CRITICAL).length,
            high: allVulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.HIGH).length,
            medium: allVulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.MEDIUM).length,
            low: allVulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.LOW).length,
            info: allVulnerabilities.filter((v) => v.severity === enums_1.VulnerabilitySeverity.INFO).length,
        };
        const statistics = {
            totalRequests: this.visitedUrls.size,
            totalResponses: this.visitedUrls.size,
            totalElements: 0,
            totalInputs: 0,
            totalPayloads: 0,
            pagesCrawled: this.visitedUrls.size,
            vulnerabilitiesBySeverity: {
                critical: summary.critical,
                high: summary.high,
                medium: summary.medium,
                low: summary.low,
                info: summary.info,
            },
            vulnerabilitiesByCategory: {},
        };
        return {
            scanId: `active-${Date.now()}`,
            targetUrl: context.config.target.url,
            status: enums_1.ScanStatus.COMPLETED,
            startTime: this.startTime,
            endTime,
            duration,
            vulnerabilities: allVulnerabilities,
            summary,
            config: context.config,
            scannerId: this.id,
            scannerName: this.name,
            scannerType: enums_1.ScannerType.ACTIVE,
            statistics,
        };
    }
    async onCleanup() {
        const context = this.getContext();
        context.logger.info('Cleaning up ActiveScanner');
        this.visitedUrls.clear();
        this.crawlQueue = [];
        context.logger.info('ActiveScanner cleanup completed');
    }
    isValidUrl(url, baseUrl) {
        try {
            const urlObj = new URL(url);
            const baseUrlObj = new URL(baseUrl);
            if (urlObj.hostname !== baseUrlObj.hostname) {
                return false;
            }
            if (this.config.skipStaticResources) {
                const staticExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.css', '.js', '.ico', '.svg', '.woff', '.ttf'];
                if (staticExtensions.some((ext) => urlObj.pathname.toLowerCase().endsWith(ext))) {
                    return false;
                }
            }
            return true;
        }
        catch (error) {
            return false;
        }
    }
    delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
    getDetectorCount() {
        return this.detectors.size;
    }
    getDetectorNames() {
        return Array.from(this.detectors.keys());
    }
    getStatistics() {
        return {
            visitedPages: this.visitedUrls.size,
            queuedPages: this.crawlQueue.length,
            maxDepth: this.config.maxDepth,
            detectorCount: this.detectors.size,
        };
    }
}
exports.ActiveScanner = ActiveScanner;
//# sourceMappingURL=ActiveScanner.js.map