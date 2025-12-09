/**
 * PageScanner - Targeted page vulnerability scanning
 * 
 * Allows scanning specific pages instead of crawling the entire application.
 * Useful for focused testing of authentication pages, forms, and critical endpoints.
 */

import { Page, Request } from 'playwright';
import { BaseScanner } from '../../core/interfaces/IScanner';
import { IActiveDetector } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult, VulnerabilitySummary } from '../../types/scan-result';
import { LogLevel, ScanStatus, VulnerabilitySeverity } from '../../types/enums';
import { DomExplorer, AttackSurfaceType } from './DomExplorer';
import { ActionHelper } from './ActionHelper';
import { 
  PageScanConfig, 
  PageTarget, 
  PageScanResult, 
  PageVulnerabilityScanResult,
  PageAction 
} from '../../types/page-scan';
import { Logger } from '../../utils/logger/Logger';

/**
 * PageScanner - Scanner that targets specific pages only
 */
export class PageScanner extends BaseScanner {
  public readonly id = 'page-scanner';
  public readonly name = 'Page Vulnerability Scanner';
  public readonly version = '1.0.0';
  public readonly type = 'active' as const;
  public readonly description = 'Targeted scanner for specific pages (login, register, etc.)';

  private pageScanConfig: PageScanConfig;
  private detectors: Map<string, IActiveDetector> = new Map();
  private domExplorer: DomExplorer;
  private pageResults: PageScanResult[] = [];
  private allVulnerabilities: Vulnerability[] = [];
  private logger: Logger;
  private actionHelper: ActionHelper;

  constructor(config: PageScanConfig) {
    super();
    this.pageScanConfig = config;
    this.domExplorer = new DomExplorer(LogLevel.INFO);
    this.logger = new Logger(LogLevel.INFO, 'PageScanner');
    this.actionHelper = new ActionHelper(config.baseUrl, this.logger);
  }

  /**
   * Register an active detector
   */
  public registerDetector(detector: IActiveDetector): void {
    this.detectors.set(detector.name, detector);
    this.logger.info(`Registered detector: ${detector.name}`);
  }

  /**
   * Register multiple detectors
   */
  public registerDetectors(detectors: IActiveDetector[]): void {
    detectors.forEach((d) => this.registerDetector(d));
  }

  /**
   * Initialize hook
   */
  protected override async onInitialize(): Promise<void> {
    this.logger.info('Initializing PageScanner');
    this.pageResults = [];
    this.allVulnerabilities = [];

    // Validate detectors
    for (const [name, detector] of this.detectors) {
      const isValid = await detector.validate();
      if (!isValid) {
        this.logger.warn(`Detector ${name} validation failed`);
      }
    }
  }

  /**
   * Execute page scan
   */
  public async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const { page, config } = context;
    const startTime = Date.now();

    this.logger.info(`Starting page scan on ${this.pageScanConfig.pages.length} pages`);

    // Perform authentication if configured
    if (this.pageScanConfig.bwappAuth) {
      await this.performBwappAuthentication(page);
    } else if (this.pageScanConfig.authentication) {
      await this.performAuthentication(page);
    }

    // Execute global pre-actions
    if (this.pageScanConfig.globalPreActions) {
      await this.actionHelper.executeActions(page, this.pageScanConfig.globalPreActions, this.delay);
    }

    // Scan each page
    const enabledPages = this.pageScanConfig.pages.filter(p => p.enabled !== false);
    
    for (const pageTarget of enabledPages) {
      try {
        const pageResult = await this.scanPage(page, pageTarget);
        this.pageResults.push(pageResult);
        
        if (this.pageScanConfig.delayBetweenPages) {
          await this.delay(this.pageScanConfig.delayBetweenPages);
        }
      } catch (error) {
        this.logger.error(`Failed to scan page ${pageTarget.url}: ${error}`);
        
        if (!this.pageScanConfig.continueOnError) {
          throw error;
        }
        
        this.pageResults.push({
          page: pageTarget,
          success: false,
          error: String(error),
          vulnerabilityCount: 0,
          duration: 0,
          attackSurfacesFound: 0,
          formsFound: 0,
          apiCallsIntercepted: 0,
        });
      }
    }

    const endTime = Date.now();

    // Generate summary
    const summary: VulnerabilitySummary = {
      total: this.allVulnerabilities.length,
      critical: this.allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL).length,
      high: this.allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.HIGH).length,
      medium: this.allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.MEDIUM).length,
      low: this.allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.LOW).length,
      info: this.allVulnerabilities.filter(v => v.severity === VulnerabilitySeverity.INFO).length,
    };

    this.logger.info(`Page scan completed. Found ${this.allVulnerabilities.length} vulnerabilities across ${this.pageResults.length} pages`);

    return {
      scanId: `page-scan-${Date.now()}`,
      targetUrl: this.pageScanConfig.baseUrl,
      status: ScanStatus.COMPLETED,
      startTime,
      endTime,
      duration: endTime - startTime,
      vulnerabilities: this.allVulnerabilities,
      summary,
      config,
    };
  }

  /**
   * Scan a single page
   */
  private async scanPage(page: Page, pageTarget: PageTarget): Promise<PageScanResult> {
    const pageStartTime = Date.now();
    const fullUrl = this.actionHelper.resolveUrl(pageTarget.url);
    
    this.logger.info(`\n${'='.repeat(60)}`);
    this.logger.info(`Scanning: ${pageTarget.name || pageTarget.url}`);
    this.logger.info(`URL: ${fullUrl}`);
    this.logger.info(`${'='.repeat(60)}`);

    const capturedRequests: Request[] = [];
    const requestListener = (request: Request) => {
      if (['xhr', 'fetch', 'document'].includes(request.resourceType())) {
        capturedRequests.push(request);
      }
    };
    page.on('request', requestListener);

    // Navigate to page
    try {
      await page.goto(fullUrl, { 
        waitUntil: 'domcontentloaded', 
        timeout: this.pageScanConfig.pageTimeout || 30000 
      });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    } catch (error) {
      page.off('request', requestListener);
      throw new Error(`Navigation failed: ${error}`);
    }

    // Execute pre-actions for this page
    if (pageTarget.preActions) {
      await this.actionHelper.executeActions(page, pageTarget.preActions, this.delay);
    }

    // Wait for specific condition if configured
    if (pageTarget.waitFor) {
      await this.waitForCondition(page, pageTarget.waitFor);
    }

    page.off('request', requestListener);

    // Discover attack surfaces
    const attackSurfaces = await this.domExplorer.explore(page, capturedRequests);
    const testableSurfaces = attackSurfaces.filter(s => 
      [AttackSurfaceType.FORM_INPUT, AttackSurfaceType.URL_PARAMETER, 
       AttackSurfaceType.API_PARAM, AttackSurfaceType.JSON_BODY].includes(s.type)
    );

    this.logger.info(`Found ${testableSurfaces.length} attack surfaces on ${pageTarget.name || pageTarget.url}`);

    // Fill forms if configured
    if (pageTarget.fillForms !== false && pageTarget.formValues) {
      await this.fillForms(page, pageTarget.formValues);
    }

    // Run detectors
    const pageVulnerabilities: Vulnerability[] = [];
    
    for (const [name, detector] of this.detectors) {
      this.logger.info(`Running detector: ${name}`);
      
      try {
        // Create detector context with all testable surfaces
        const detectorContext = {
          page,
          attackSurfaces: testableSurfaces,
          baseUrl: fullUrl,
        };
        
        const vulns = await detector.detect(detectorContext);
        if (vulns.length > 0) {
          // Add page context to vulnerabilities
          vulns.forEach(v => {
            v.metadata = {
              ...v.metadata,
              pageName: pageTarget.name,
              pageUrl: pageTarget.url,
            };
          });
          pageVulnerabilities.push(...vulns);
          this.allVulnerabilities.push(...vulns);
          
          // Emit vulnerabilities
          vulns.forEach(v => {
            if (this.context?.emitVulnerability) {
              this.context.emitVulnerability(v);
            }
          });
        }
      } catch (error) {
        this.logger.warn(`Detector ${name} failed: ${error}`);
      }
    }

    const pageEndTime = Date.now();

    return {
      page: pageTarget,
      success: true,
      vulnerabilityCount: pageVulnerabilities.length,
      duration: pageEndTime - pageStartTime,
      attackSurfacesFound: testableSurfaces.length,
      formsFound: attackSurfaces.filter(s => s.type === AttackSurfaceType.FORM_INPUT).length,
      apiCallsIntercepted: capturedRequests.filter(r => ['xhr', 'fetch'].includes(r.resourceType())).length,
    };
  }

  // Shared action/URL helpers now live in ActionHelper

  /**
   * Wait for a condition before scanning
   */
  private async waitForCondition(page: Page, condition: PageTarget['waitFor']): Promise<void> {
    if (!condition) return;

    const timeout = condition.timeout || 10000;

    switch (condition.type) {
      case 'selector':
        await page.waitForSelector(String(condition.value), { timeout });
        break;
      case 'navigation':
        await page.waitForURL(String(condition.value), { timeout });
        break;
      case 'networkidle':
        await page.waitForLoadState('networkidle', { timeout });
        break;
      case 'timeout':
        await this.delay(Number(condition.value) || 1000);
        break;
      case 'function':
        if (typeof condition.value === 'string') {
          await page.waitForFunction(condition.value, { timeout });
        }
        break;
    }
  }

  /**
   * Fill forms with provided values
   */
  private async fillForms(page: Page, formValues: Record<string, string>): Promise<void> {
    for (const [field, value] of Object.entries(formValues)) {
      try {
        // Try multiple selector strategies
        const selectors = [
          `[formcontrolname="${field}"]`,
          `[name="${field}"]`,
          `#${field}`,
          `input[placeholder*="${field}" i]`,
          `[aria-label*="${field}" i]`,
        ];

        for (const selector of selectors) {
          const element = await page.$(selector);
          if (element) {
            await element.fill(value);
            this.logger.debug(`Filled ${field} with test value`);
            break;
          }
        }
      } catch (error) {
        this.logger.warn(`Could not fill field ${field}: ${error}`);
      }
    }
  }

  /**
   * Perform authentication
   */
  private async performAuthentication(page: Page): Promise<void> {
    const auth = this.pageScanConfig.authentication;
    if (!auth) return;

    this.logger.info('Performing authentication...');
    
    const loginUrl = this.actionHelper.resolveUrl(auth.loginUrl);
    await page.goto(loginUrl, { waitUntil: 'domcontentloaded' });
    await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});
    
    await this.actionHelper.executeActions(page, auth.loginActions, this.delay);

    // Verify login success
    if (auth.successIndicator) {
      try {
        if (auth.successIndicator.type === 'selector') {
          await page.waitForSelector(auth.successIndicator.value, { timeout: 10000 });
        } else {
          await page.waitForURL(auth.successIndicator.value, { timeout: 10000 });
        }
        this.logger.info('Authentication successful');
      } catch {
        this.logger.warn('Could not verify authentication success');
      }
    }
  }

  /**
   * Built-in authentication flow for bWAPP instances.
   * Uses defaults (bee/bug, low security) unless overridden via bwappAuth config.
   */
  private async performBwappAuthentication(page: Page): Promise<void> {
    const auth = this.pageScanConfig.bwappAuth;
    if (!auth) return;

    const username = auth.username ?? 'bee';
    const password = auth.password ?? 'bug';
    const securityLevel = auth.securityLevel ?? '0';
    const loginPath = auth.loginUrl ?? '/login.php';
    const portalPath = auth.portalPath ?? '/portal.php';

    const loginUrl = this.actionHelper.resolveUrl(loginPath);
    const actions: PageAction[] = [
      { type: 'navigate', value: loginUrl, description: 'Open bWAPP login page' },
      { type: 'fill', selector: 'input[name="login"]', value: username, description: 'Fill username' },
      { type: 'fill', selector: 'input[name="password"]', value: password, description: 'Fill password' },
      { type: 'select', selector: 'select[name="security_level"]', value: securityLevel, description: 'Select security level' },
      { type: 'click', selector: '[name="form"]', description: 'Submit login form' },
    ];

    this.logger.info(`Performing bWAPP authentication as ${username} (security level ${securityLevel})`);

    await this.actionHelper.executeActions(page, actions, this.delay);

    // Verify login success
    try {
      await page.waitForURL(`**${portalPath}`, { timeout: 10000 });
      this.logger.info('bWAPP authentication successful');
    } catch (error) {
      this.logger.warn(`bWAPP authentication verification failed: ${error}`);
    }
  }

  /**
   * Get page scan results
   */
  public getPageResults(): PageVulnerabilityScanResult {
    const successfulPages = this.pageResults.filter(r => r.success).length;
    const failedPages = this.pageResults.filter(r => !r.success).length;
    const totalDuration = this.pageResults.reduce((sum, r) => sum + r.duration, 0);

    return {
      pageResults: this.pageResults,
      totalVulnerabilities: this.allVulnerabilities.length,
      successfulPages,
      failedPages,
      totalDuration,
      summary: this.pageResults.map(r => ({
        pageName: r.page.name || r.page.url,
        pageUrl: r.page.url,
        vulnerabilities: r.vulnerabilityCount,
        status: r.success ? 'success' : 'failed',
      })),
    };
  }

  /**
   * Cleanup hook
   */
  protected override async onCleanup(): Promise<void> {
    this.logger.info('PageScanner cleanup complete');
  }

  /**
   * Check if scanner is enabled
   */
  public override isEnabled(config: any): boolean {
    return config.scanners?.active?.enabled !== false;
  }

  /**
   * Utility delay function
   */
  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
