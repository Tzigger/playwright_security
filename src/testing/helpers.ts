/**
 * Playwright test helpers for security testing
 * 
 * These utilities integrate security scanning into your Playwright tests.
 * For comprehensive scanning, use the dast-scan CLI or ScanEngine API.
 * 
 * @example Basic usage in Playwright test:
 * ```typescript
 * import { test, expect } from '@playwright/test';
 * import { runSecurityScan } from 'playwright_security/testing';
 * 
 * test('login form should be secure', async ({ page }) => {
 *   await page.goto('https://myapp.com/login');
 *   
 *   const vulns = await runSecurityScan(page.url());
 *   
 *   // Fail test if critical vulnerabilities found
 *   const critical = vulns.filter(v => v.severity === 'critical');
 *   expect(critical).toHaveLength(0);
 * });
 * ```
 */
import { ScanEngine } from '../core/engine/ScanEngine';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { SqlInjectionDetector } from '../detectors/active/SqlInjectionDetector';
import { XssDetector } from '../detectors/active/XssDetector';
import { ErrorBasedDetector } from '../detectors/active/ErrorBasedDetector';
import { Vulnerability } from '../types/vulnerability';
import { VulnerabilitySeverity, AuthType, BrowserType, LogLevel, ReportFormat, VerbosityLevel, AggressivenessLevel } from '../types/enums';
import { ScanConfiguration } from '../types/config';

export interface SecurityScanOptions {
  /** Custom detectors to use. If not provided, uses defaults (SQL, XSS, Error) */
  detectors?: 'all' | 'sql' | 'xss' | 'errors';
  /** Maximum pages to scan */
  maxPages?: number;
  /** Run in headless mode */
  headless?: boolean;
}

/**
 * Run a security scan on a URL
 * This creates a new browser context and scans the target
 * 
 * @example
 * const vulns = await runSecurityScan('https://myapp.com');
 * expect(vulns).toHaveLength(0);
 */
export async function runSecurityScan(
  targetUrl: string,
  options: SecurityScanOptions = {}
): Promise<Vulnerability[]> {
  const config: ScanConfiguration = {
    target: {
      url: targetUrl,
      authentication: { type: AuthType.NONE },
      crawlDepth: 1,
      maxPages: options.maxPages || 5,
      timeout: 30000,
    },
    scanners: {
      passive: { enabled: false },
      active: {
        enabled: true,
        aggressiveness: AggressivenessLevel.MEDIUM,
        submitForms: true,
      },
    },
    detectors: {
      enabled: [],
      sensitivity: 'normal' as any,
    },
    browser: {
      type: BrowserType.CHROMIUM,
      headless: options.headless !== false,
      timeout: 30000,
      viewport: { width: 1280, height: 800 },
    },
    reporting: {
      formats: [ReportFormat.JSON],
      outputDir: './test-security-reports',
      verbosity: VerbosityLevel.NORMAL,
    },
    advanced: {
      parallelism: 1,
      logLevel: LogLevel.WARN, // Less verbose in tests
    },
  };

  const engine = new ScanEngine();
  const scanner = new ActiveScanner();
  
  // Register detectors based on options
  const detectors = [];
  if (!options.detectors || options.detectors === 'all') {
    detectors.push(new SqlInjectionDetector(), new XssDetector(), new ErrorBasedDetector());
  } else if (options.detectors === 'sql') {
    detectors.push(new SqlInjectionDetector());
  } else if (options.detectors === 'xss') {
    detectors.push(new XssDetector());
  } else if (options.detectors === 'errors') {
    detectors.push(new ErrorBasedDetector());
  }
  
  scanner.registerDetectors(detectors);
  engine.registerScanner(scanner);
  
  await engine.loadConfiguration(config);
  const result = await engine.scan();
  await engine.cleanup();
  
  return result.vulnerabilities;
}

/**
 * Assert no vulnerabilities above a certain severity
 * Throws an error with details if vulnerabilities are found
 * 
 * @example
 * await assertNoVulnerabilities(vulns, VulnerabilitySeverity.MEDIUM);
 */
export function assertNoVulnerabilities(
  vulnerabilities: Vulnerability[],
  maxAllowedSeverity: VulnerabilitySeverity = VulnerabilitySeverity.INFO
): void {
  const severityOrder = [
    VulnerabilitySeverity.INFO,
    VulnerabilitySeverity.LOW,
    VulnerabilitySeverity.MEDIUM,
    VulnerabilitySeverity.HIGH,
    VulnerabilitySeverity.CRITICAL,
  ];
  
  const maxIndex = severityOrder.indexOf(maxAllowedSeverity);
  const violations = vulnerabilities.filter(v => 
    severityOrder.indexOf(v.severity) > maxIndex
  );
  
  if (violations.length > 0) {
    const summary = violations
      .map(v => `  - [${v.severity.toUpperCase()}] ${v.title}`)
      .join('\n');
    
    throw new Error(
      `Security vulnerabilities found above ${maxAllowedSeverity} severity:\n${summary}\n\n` +
      `Total: ${violations.length} vulnerability(ies)`
    );
  }
}

// Re-export severity enum for convenience
export { VulnerabilitySeverity };

