import { Page } from 'playwright';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilityCategory, LogLevel } from '../../types/enums';
import { Logger } from '../../utils/logger/Logger';
import { TimeBasedVerifier } from './techniques/TimeBasedVerifier';
import { ResponseDiffVerifier } from './techniques/ResponseDiffVerifier';
import { VerificationConfig, VerificationStatus, VerificationLevel } from '../../types/verification';

/**
 * Verification Engine
 * 
 * Responsible for verifying potential vulnerabilities by re-executing payloads
 * and checking for successful execution indicators (e.g. alerts, specific DOM states).
 */
export class VerificationEngine {
  private logger: Logger;
  private timeBasedVerifier: TimeBasedVerifier;
  private responseDiffVerifier: ResponseDiffVerifier;

  constructor() {
    this.logger = new Logger(LogLevel.INFO, 'VerificationEngine');
    this.timeBasedVerifier = new TimeBasedVerifier();
    this.responseDiffVerifier = new ResponseDiffVerifier();
  }

  /**
   * Verify a candidate vulnerability
   */
  public async verify(page: Page, vulnerability: Vulnerability): Promise<boolean> {
    this.logger.info(`Verifying vulnerability: ${vulnerability.title} (${vulnerability.id})`);

    // Set page for verifiers
    this.timeBasedVerifier.setPage(page);
    this.responseDiffVerifier.setPage(page);

    const config: VerificationConfig = {
      level: VerificationLevel.STANDARD,
      maxRetries: 2,
      payloadVariation: true,
      attemptTimeout: 10000
    };

    try {
      // 1. Time-based verification (SQLi, Command Injection)
      if (this.isTimeBased(vulnerability)) {
        const result = await this.timeBasedVerifier.verify(vulnerability, config);
        if (result.status === VerificationStatus.CONFIRMED) {
          this.logger.info(`Vulnerability confirmed via Time-Based Verification: ${vulnerability.title}`);
          return true;
        }
        if (result.status === VerificationStatus.FALSE_POSITIVE) {
          this.logger.info(`Vulnerability marked as False Positive via Time-Based Verification: ${vulnerability.title}`);
          return false;
        }
      }

      // 2. Response Diff verification (Boolean SQLi, XSS, etc.)
      if (this.isDiffBased(vulnerability)) {
        const result = await this.responseDiffVerifier.verify(vulnerability, config);
        if (result.status === VerificationStatus.CONFIRMED) {
          this.logger.info(`Vulnerability confirmed via Response Diff Verification: ${vulnerability.title}`);
          return true;
        }
        if (result.status === VerificationStatus.FALSE_POSITIVE) {
          this.logger.info(`Vulnerability marked as False Positive via Response Diff Verification: ${vulnerability.title}`);
          return false;
        }
      }

      // 3. Fallback to basic checks if specialized verifiers are inconclusive or not applicable
      switch (vulnerability.category) {
        case VulnerabilityCategory.XSS:
          return this.verifyXss(page, vulnerability);
        case VulnerabilityCategory.INJECTION:
          if (vulnerability.title.includes('SQL')) {
            return this.verifySqli(page, vulnerability);
          }
          return true;
        default:
          return true;
      }
    } catch (error) {
      this.logger.error(`Verification failed with error: ${error}`);
      return true; // Fail open (report it) if verification crashes, to avoid false negatives
    }
  }

  private isTimeBased(vulnerability: Vulnerability): boolean {
    const title = vulnerability.title.toLowerCase();
    return title.includes('time-based') || 
           title.includes('sleep') || 
           title.includes('delay') ||
           (vulnerability.evidence?.metadata as any)?.technique === 'time-based';
  }

  private isDiffBased(vulnerability: Vulnerability): boolean {
    const title = vulnerability.title.toLowerCase();
    return title.includes('boolean') || 
           title.includes('error-based') ||
           title.includes('reflected') ||
           (vulnerability.evidence?.metadata as any)?.technique === 'boolean-based';
  }

  /**
   * Verify XSS by checking for alert dialogs or DOM execution
   */
  private async verifyXss(page: Page, vulnerability: Vulnerability): Promise<boolean> {
    const payload = vulnerability.evidence?.request?.body || 
                    (vulnerability.evidence?.metadata as any)?.payload;
    const url = vulnerability.url;

    if (!payload || !url) {
      this.logger.warn('Missing payload or URL for XSS verification');
      return false;
    }

    let dialogDetected = false;
    const dialogHandler = async (dialog: any) => {
      this.logger.info(`Dialog detected: ${dialog.message()}`);
      dialogDetected = true;
      await dialog.dismiss().catch(() => {});
    };

    page.on('dialog', dialogHandler);

    try {
      // 1. Navigate/Inject
      // If it's a GET request (Reflected/DOM), navigation is usually enough
      if (vulnerability.evidence?.request?.method === 'GET') {
        this.logger.info(`Navigating to ${url} for XSS check`);
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
      } else {
        // For POST/Stored, we might need to re-inject or just visit the page if it's stored
        // Assuming the vulnerability URL is where it triggers
        await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 10000 }).catch(() => {});
      }

      // 2. Wait for execution
      await page.waitForTimeout(2000);

      // 3. Check for DOM artifacts (if no dialog)
      if (!dialogDetected) {
        // Check if the script tag is present AND unescaped
        // Or if specific execution markers are present (e.g. window.__xss_mark__)
        const executionConfirmed = await page.evaluate((payloadStr) => {
          // Check for window variable if used in payload
          if ((window as any).__xss_mark__) return true;
          
          // Check if payload exists in DOM as raw HTML (not text content)
          // This is a heuristic
          if (document.documentElement.innerHTML.includes(payloadStr)) {
             // Basic check: is it inside a script tag?
             // This logic needs to be robust. 
             // If payload is <script>alert(1)</script>, finding it in innerHTML is good sign,
             // BUT we must ensure it's not &lt;script&gt;
             // innerHTML returns entity-encoded strings for attributes, but usually raw for tags.
             return true; 
          }
          return false;
        }, payload);
        
        if (executionConfirmed) {
            this.logger.info('XSS execution marker found in DOM');
            return true;
        }
      }

      if (dialogDetected) {
        this.logger.info('XSS Verified via Dialog');
        return true;
      }

      this.logger.info('XSS Verification Failed - No execution detected');
      return false;

    } catch (error) {
      this.logger.error(`XSS verification error: ${error}`);
      return false;
    } finally {
      page.off('dialog', dialogHandler);
    }
  }

  /**
   * Verify SQL Injection
   * Improve boolean logic checks
   */
  private async verifySqli(_page: Page, vulnerability: Vulnerability): Promise<boolean> {
    // For SQLi, "Verification" is hard if we just have the report.
    // We primarily rely on the detector's logic.
    // However, we can filter out obvious false positives like 500 errors being marked as "Boolean Based".
    
    const responseStatus = vulnerability.evidence?.response?.status;
    const technique = (vulnerability.evidence?.metadata as any)?.technique;

    if (technique === 'boolean-based' && responseStatus === 500) {
      this.logger.info('Marking Boolean-Based SQLi as False Positive due to 500 status code (indicates Error-Based/Disclosure)');
      return false;
    }
    
    // Check if the error message is generic HTML (e.g. standard Express/Nginx 500 page)
    // vs a specific SQL error. If it's a generic page without SQL syntax, it's likely a FP.
    const body = vulnerability.evidence?.response?.body || '';
    if (responseStatus === 500 && !body.match(/SQL|syntax|database|ODBC|JDBC/i)) {
         this.logger.info('Marking SQLi as False Positive: 500 error without SQL keywords');
         return false;
    }

    return true;
  }
}