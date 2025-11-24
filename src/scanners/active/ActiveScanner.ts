import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, ScanStatistics, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity, ScannerType } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';

/**
 * Configurare ActiveScanner
 */
export interface ActiveScannerConfig {
  maxDepth?: number;              // Adâncime maximă pentru crawling
  maxPages?: number;              // Număr maxim de pagini de scanat
  delayBetweenRequests?: number;  // Delay între request-uri (ms)
  followRedirects?: boolean;      // Urmărește redirect-urile
  respectRobotsTxt?: boolean;     // Respectă robots.txt
  userAgent?: string;             // User agent custom
  skipStaticResources?: boolean;  // Skip imagini, CSS, JS
  aggressiveness?: 'low' | 'medium' | 'high'; // Nivel de agresivitate
}

/**
 * ActiveScanner - Scanner activ care injectează payload-uri pentru detectarea vulnerabilităților
 */
export class ActiveScanner extends BaseScanner {
  public readonly id = 'active-scanner';
  public readonly name = 'Active Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'active' as const;
  public readonly description = 'Active scanner with payload injection and fuzzing capabilities';

  private config: ActiveScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private visitedUrls: Set<string> = new Set();
  private crawlQueue: string[] = [];

  constructor(config: ActiveScannerConfig = {}) {
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

    this.domExplorer = new DomExplorer(LogLevel.INFO);
  }

  /**
   * Înregistrează un detector activ
   */
  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.context?.logger.info(`Registered active detector: ${detector.name}`);
  }

  /**
   * Înregistrează multiple detectori
   */
  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach((detector) => this.registerDetector(detector));
  }

  /**
   * Initialize hook
   */
  protected override async onInitialize(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Initializing ActiveScanner');
    
    // Clear state
    this.visitedUrls.clear();
    this.crawlQueue = [];

    // Validate detectors
    for (const [name, detector] of this.detectors) {
      const isValid = await detector.validate();
      if (!isValid) {
        context.logger.warn(`Detector ${name} validation failed`);
      }
    }

    context.logger.info('ActiveScanner initialized successfully');
  }

  /**
   * Execute scan
   */
  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    const targetUrl = config.target.url;

    context.logger.info(`Starting active scan on: ${targetUrl}`);
    const allVulnerabilities: Vulnerability[] = [];

    try {
      // Add target to crawl queue
      this.crawlQueue.push(targetUrl);

      // Crawl and scan pages
      let depth = 0;
      while (this.crawlQueue.length > 0 && depth < this.config.maxDepth!) {
        const url = this.crawlQueue.shift()!;

        if (this.visitedUrls.has(url) || this.visitedUrls.size >= this.config.maxPages!) {
          continue;
        }

        context.logger.info(`Scanning page [${this.visitedUrls.size + 1}/${this.config.maxPages}]: ${url}`);

        // Navigate to page
        try {
          await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
          await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
        } catch (error) {
          context.logger.warn(`Failed to navigate to ${url}: ${error}`);
          continue;
        }

        this.visitedUrls.add(url);

        // Discover attack surfaces
        const allSurfaces = await this.domExplorer.explore(page);
        // Only keep supported types for injection
        const supportedTypes = [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER, AttackSurfaceType.COOKIE];
        const attackSurfaces = allSurfaces.filter(s => supportedTypes.includes(s.type));
        context.logger.info(`Found ${attackSurfaces.length} supported attack surfaces on ${url}`);

        // Run all active detectors
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
              // Emit vulnerabilities immediately
              vulns.forEach(vuln => context.emitVulnerability?.(vuln));
            }
          } catch (error) {
            context.logger.error(`Detector ${name} failed: ${error}`);
          }

          await this.delay(this.config.delayBetweenRequests!);
        }

        // Discover new links for crawling
        const links = attackSurfaces.filter(s => s.type === AttackSurfaceType.LINK);
        
        for (const link of links) {
          if (link.value && !this.visitedUrls.has(link.value) && this.isValidUrl(link.value, targetUrl)) {
            this.crawlQueue.push(link.value);
          }
        }

        depth++;
        await this.delay(this.config.delayBetweenRequests!);
      }

      context.logger.info(`Active scan completed. Found ${allVulnerabilities.length} vulnerabilities`);
    } catch (error) {
      context.logger.error(`Active scan failed: ${error}`);
    }

    const endTime = new Date();
    const duration = endTime.getTime() - this.startTime!.getTime();

    // Calculate summary
    const summary: VulnerabilitySummary = {
      total: allVulnerabilities.length,
      critical: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.LOW).length,
      info: allVulnerabilities.filter((v) => v.severity === VulnerabilitySeverity.INFO).length,
    };

    // Calculate statistics
    const statistics: ScanStatistics = {
      totalRequests: this.visitedUrls.size,
      totalResponses: this.visitedUrls.size,
      totalElements: 0, // Will be populated by detectors
      totalInputs: 0, // Will be populated by detectors
      totalPayloads: 0, // Will be populated by detectors
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
      status: ScanStatus.COMPLETED,
      startTime: this.startTime!,
      endTime,
      duration,
      vulnerabilities: allVulnerabilities,
      summary,
      config: context.config,
      scannerId: this.id,
      scannerName: this.name,
      scannerType: ScannerType.ACTIVE,
      statistics,
    };
  }

  /**
   * Cleanup hook
   */
  protected override async onCleanup(): Promise<void> {
    const context = this.getContext();
    context.logger.info('Cleaning up ActiveScanner');
    this.visitedUrls.clear();
    this.crawlQueue = [];
    context.logger.info('ActiveScanner cleanup completed');
  }

  /**
   * Validează dacă URL-ul este valid pentru crawling
   */
  private isValidUrl(url: string, baseUrl: string): boolean {
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
    } catch (error) {
      return false;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  public getDetectorCount(): number {
    return this.detectors.size;
  }

  public getDetectorNames(): string[] {
    return Array.from(this.detectors.keys());
  }

  public getStatistics(): {
    visitedPages: number;
    queuedPages: number;
    maxDepth: number;
    detectorCount: number;
  } {
    return {
      visitedPages: this.visitedUrls.size,
      queuedPages: this.crawlQueue.length,
      maxDepth: this.config.maxDepth!,
      detectorCount: this.detectors.size,
    };
  }
}
