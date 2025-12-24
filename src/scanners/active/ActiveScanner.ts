import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, ScanStatistics, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity, ScannerType } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';
import { Request } from 'playwright';
import { VerificationEngine } from '../../core/verification/VerificationEngine';
import { TimeoutManager } from '../../core/timeout/TimeoutManager';
import { SPAWaitStrategy } from '../../core/timeout/SPAWaitStrategy';
import { OperationType } from '../../types/timeout';
import { SessionManager } from '../../core/auth/SessionManager'; // Ensure you created this file from Phase 2

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
  safeMode?: boolean;             // Explicit safe mode override
}

/**
 * ActiveScanner - Scanner activ care injectează payload-uri pentru detectarea vulnerabilităților
 * 
 * Features v0.2+:
 * - Smart Timeout Management (Anti-Hang)
 * - SPA Wait Strategy (Angular/React support)
 * - Active Verification (False Positive Reduction)
 * - Session Management (Auto-Login)
 * - Deep API Discovery (JS Analysis)
 */
export class ActiveScanner extends BaseScanner {
  public readonly id = 'active-scanner';
  public readonly name = 'Active Scanner';
  public readonly version = '1.1.0';
  public readonly type = 'active' as const;
  public readonly description = 'Active scanner with payload injection, fuzzing, and smart SPA navigation';

  private config: ActiveScannerConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private verificationEngine: VerificationEngine;
  private timeoutManager: TimeoutManager;
  private spaWaitStrategy: SPAWaitStrategy;
  private sessionManager: SessionManager;
  private visitedUrls: Set<string> = new Set();
  private crawlQueue: string[] = [];

  constructor(config: ActiveScannerConfig = {}) {
    super();
    // PERFORMANCE FIX: Reduce default delay from 500ms to 100ms
    // Concurrency is now handled at the injection level
    this.config = {
      maxDepth: config.maxDepth || 3,
      maxPages: config.maxPages || 20,
      delayBetweenRequests: config.delayBetweenRequests ?? 100,
      followRedirects: config.followRedirects !== false,
      respectRobotsTxt: config.respectRobotsTxt !== false,
      skipStaticResources: config.skipStaticResources !== false,
      aggressiveness: config.aggressiveness || 'medium',
      ...config,
    };

    this.domExplorer = new DomExplorer(LogLevel.INFO);
    this.verificationEngine = new VerificationEngine();
    this.timeoutManager = new TimeoutManager();
    this.spaWaitStrategy = new SPAWaitStrategy();
    this.sessionManager = new SessionManager(LogLevel.INFO);
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

    // Configure Session Manager from Context
    const authConfig = context.config.target.authentication;
    if (authConfig?.credentials && authConfig.credentials.username) {
        this.sessionManager.configure(
            authConfig.loginPage?.url || context.config.target.url + '/login', // Heuristic default
            authConfig.credentials.username,
            authConfig.credentials.password || ''
        );
        context.logger.info('Session Manager configured with credentials.');
    }

    // Configure Timeout Manager based on aggressiveness
    if (this.config.aggressiveness === 'high') {
        this.timeoutManager.usePreset('thorough');
    } else {
        this.timeoutManager.usePreset('default');
    }

    // Validate detectors
    for (const [name, detector] of this.detectors) {
      // Apply configuration if available
      const tuning = context.config.detectors?.tuning;
      const sqliTuning = tuning?.['sqli'];
      if (sqliTuning && name === 'SqlInjectionDetector') {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if (typeof (detector as any).updateConfig === 'function') {
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          (detector as any).updateConfig({ tuning: sqliTuning });
          context.logger.debug(`Applied tuning configuration to ${name}`);
        }
      }

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
    
    // In SPA mode, use current page URL as starting point; otherwise use config target URL
    const currentUrl = page.url();
    const targetUrl = currentUrl && currentUrl !== 'about:blank' ? currentUrl : config.target.url;

    context.logger.info(`Starting active scan on: ${targetUrl}`);
    const allVulnerabilities: Vulnerability[] = [];
    
    // 1. Attempt Auto-Login if configured
    // This allows "Blackbox" scanning without manual cookie extraction
    await this.sessionManager.performAutoLogin(page);

    // Add target to crawl queue
    this.crawlQueue.push(targetUrl);
    
    const clickedElements = new Set<string>(); // Track clicked elements to avoid loops
    let depth = 0;
    
    while (this.crawlQueue.length > 0 && depth < this.config.maxDepth!) {
      // Process queue in small batches
      const batchSize = 1; 
      const batch = this.crawlQueue.splice(0, batchSize);
      
      for (const url of batch) {
        if (this.visitedUrls.has(url) || this.visitedUrls.size >= this.config.maxPages!) continue;
        
        context.logger.info(`Scanning page [${this.visitedUrls.size + 1}/${this.config.maxPages}]: ${url}`);
        this.visitedUrls.add(url);

        // Start Passive-to-Active Monitoring
        this.domExplorer.clearDynamicSurfaces();
        this.domExplorer.startMonitoring(page);

        // Capture requests
        const capturedRequests: Request[] = [];
        const requestListener = (request: Request) => {
          if (['xhr', 'fetch', 'document'].includes(request.resourceType())) {
            capturedRequests.push(request);
          }
        };
        page.on('request', requestListener);

        // --- NAVIGATION LOGIC ---
        const currentPageUrl = page.url();
        const needsNavigation = currentPageUrl !== url;
        
        if (needsNavigation) {
          try {
            const timeout = this.timeoutManager.getTimeout(OperationType.NAVIGATION);
            
            // Execute navigation with timeout protection
            await page.goto(url, { waitUntil: 'domcontentloaded', timeout });
            
            // Use SPA Wait Strategy for intelligent waiting (Angular/React/Vue)
            await this.spaWaitStrategy.waitForStability(page, timeout, 'navigation');
            
          } catch (error) {
            context.logger.warn(`Failed to navigate to ${url}: ${error}`);
            page.off('request', requestListener);
            this.domExplorer.stopMonitoring(page);
            continue;
          }
        } else {
          context.logger.info('Already on target page, skipping navigation (SPA mode)');
        }

        // --- DEEP API DISCOVERY (New Feature) ---
        // Scan loaded JS files for hidden API endpoints (e.g. /rest/admin/application-configuration)
        try {
            const jsEndpoints = await this.domExplorer.extractEndpointsFromJS(page);
            for (const endpoint of jsEndpoints) {
                try {
                    const fullApiUrl = new URL(endpoint, url).toString();
                    if (!this.visitedUrls.has(fullApiUrl) && this.isValidUrl(fullApiUrl, targetUrl)) {
                        // Treat endpoints as visitable URLs to see if they reflect input or are accessible
                        // Ideally we'd probe them directly, but adding to queue is a good "Blackbox" approach
                        if (!this.crawlQueue.includes(fullApiUrl)) {
                            this.crawlQueue.push(fullApiUrl);
                            context.logger.debug(`Added hidden JS endpoint to queue: ${endpoint}`);
                        }
                    }
                } catch (e) { /* invalid url construction */ }
            }
        } catch (e) {
            context.logger.warn(`JS Endpoint discovery failed: ${e}`);
        }

        page.off('request', requestListener);
        this.domExplorer.stopMonitoring(page);

        // Detect SPA framework and handle hash routes
        await this.domExplorer.detectSPAFramework(page);
        const hashRoutes = await this.domExplorer.extractHashRoutes(page);
        
        // Add hash routes to crawl queue
        if (hashRoutes.length > 0) {
          context.logger.info(`Found ${hashRoutes.length} hash routes`);
          const baseUrl = page.url().split('#')[0];
          hashRoutes.forEach(route => {
            const fullUrl = baseUrl + route;
            if (!this.visitedUrls.has(fullUrl)) {
              this.crawlQueue.push(fullUrl);
            }
          });
        }

        // Discover attack surfaces
        let allSurfaces = await this.domExplorer.explore(page, capturedRequests);
        
        // Retry logic for slow SPAs using updated Wait Strategy
        if (allSurfaces.length === 0) {
            context.logger.info('No surfaces found initially, waiting for potential SPA hydration...');
            await this.spaWaitStrategy.waitForStability(page, 3000, 'navigation');
            allSurfaces = await this.domExplorer.explore(page, capturedRequests);
            
            if (allSurfaces.length === 0) {
                 await this.spaWaitStrategy.waitForStability(page, 2000, 'navigation');
                 allSurfaces = await this.domExplorer.explore(page, capturedRequests);
            }
        }
        
        // Filter surfaces for testing
        const attackSurfaces = allSurfaces.filter(s => 
          [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER, AttackSurfaceType.COOKIE, AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY, AttackSurfaceType.BUTTON].includes(s.type)
        );
        
        context.logger.info(`Found ${attackSurfaces.length} supported attack surfaces on ${url}`);

        // --- 1. HANDLE CLICKS (Interaction) ---
        const clickables = attackSurfaces.filter(s => s.type === AttackSurfaceType.BUTTON);
        let clickCount = 0;
        const MAX_CLICKS_PER_PAGE = 5;

        for (const clickable of clickables) {
          if (clickCount >= MAX_CLICKS_PER_PAGE) break;
          
          const clickId = `${url}-${clickable.name}-${clickable.metadata['text']}`;
          if (clickedElements.has(clickId)) continue;
          
          if (clickable.element) {
            try {
              context.logger.debug(`Clicking element: ${clickable.name}`);
              
              // New: Smart Form Preparation is handled inside DomExplorer.explore(),
              // so the fields should be pre-filled with dummy data, making the button active.

              clickedElements.add(clickId);
              clickCount++;
              
              const clickRequests: Request[] = [];
              const clickListener = (req: Request) => { if (['xhr', 'fetch'].includes(req.resourceType())) clickRequests.push(req); };
              page.on('request', clickListener);

              await clickable.element.click({ timeout: 1000 }).catch(() => {});
              
              // Use SPA Wait Strategy instead of simple network idle
              await this.spaWaitStrategy.waitForStability(page, 2000, 'api');
              
              page.off('request', clickListener);

              // Check for new URL
              const newUrl = page.url();
              if (newUrl !== url && !this.visitedUrls.has(newUrl) && this.isValidUrl(newUrl, targetUrl)) {
                this.crawlQueue.push(newUrl);
              }

              // Add new API surfaces found via click
              if (clickRequests.length > 0) {
                context.logger.info(`Captured ${clickRequests.length} requests from interaction`);
                const newSurfaces = await this.domExplorer.explore(page, clickRequests);
                const newApis = newSurfaces.filter(s => [AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type));
                
                if (newApis.length > 0) {
                    context.logger.info(`Discovered ${newApis.length} new API attack surfaces`);
                    attackSurfaces.push(...newApis);
                }
              }
              
              // Restore if navigated away
              if (page.url() !== url) await page.goto(url, { waitUntil: 'domcontentloaded' });

            } catch (e) { /* ignore */ }
          }
        }

        // --- 2. RUN ACTIVE DETECTORS ---
        // Only run on data surfaces (not buttons)
        const testableSurfaces = attackSurfaces.filter(s => s.type !== AttackSurfaceType.BUTTON);

        // Determine safe mode status
        const safeMode = this.config.safeMode ?? config.scanners.active?.safeMode ?? false;
        
        for (const [name, detector] of this.detectors) {
          try {
            context.logger.debug(`Running detector: ${name}`);
            const vulns = await detector.detect({ page, attackSurfaces: testableSurfaces, baseUrl: url, safeMode });
            
            if (vulns.length > 0) {
              context.logger.info(`Detector ${name} found ${vulns.length} potential vulnerabilities. Verifying...`);
              
              const verifiedVulns: Vulnerability[] = [];
              for (const vuln of vulns) {
                // VERIFICATION ENGINE: Double-check results
                const isVerified = await this.verificationEngine.verify(page, vuln);

                if (isVerified) {
                  vuln.confirmed = true;
                  if (!vuln.evidence.metadata) vuln.evidence.metadata = {};
                  (vuln.evidence.metadata as any).verificationStatus = 'confirmed';
                  
                  context.logger.info(`[CONFIRMED] ${vuln.title}`);
                  verifiedVulns.push(vuln);
                } else {
                  context.logger.info(`[FALSE POSITIVE] Discarded ${vuln.title}`);
                }
              }

              if (verifiedVulns.length > 0) {
                allVulnerabilities.push(...verifiedVulns);
                verifiedVulns.forEach(v => context.emitVulnerability?.(v));
              }
            }
          } catch (error: any) {
            // ROBUSTNESS: Handle browser closed error gracefully
            if (error.message && (error.message.includes('closed') || error.message.includes('destroyed'))) {
                context.logger.error(`Browser context closed unexpectedly during ${name}. Attempting to recover next page...`);
                // Break inner loop to skip other detectors on this dead page
                break; 
            }
            context.logger.error(`Detector ${name} failed: ${error}`);
          }
        }

        // 3. Discover new links for crawling
        const links = attackSurfaces.filter(s => s.type === AttackSurfaceType.LINK);
        for (const link of links) {
          if (link.value && !this.visitedUrls.has(link.value) && this.isValidUrl(link.value, targetUrl)) {
            this.crawlQueue.push(link.value);
          }
        }
      }
      depth++;
    }

    context.logger.info(`Active scan completed. Found ${allVulnerabilities.length} vulnerabilities`);
    
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

      // Same origin policy for crawling
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