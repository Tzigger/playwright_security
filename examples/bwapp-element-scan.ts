/**
 * bWAPP Element Vulnerability Scan
 *
 * Targets specific elements using explicit locators for precise testing.
 *
 * Usage:
 *   npx tsx ./examples/bwapp-element-scan.ts
 */

import { chromium, Browser } from 'playwright';
import { ElementScanner } from '../src/scanners/active/ElementScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { ElementScanConfig } from '../src/types/element-scan';
import { AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';
import { Vulnerability } from '../src/types/vulnerability';
import { Logger } from '../src/utils/logger/Logger';
import {
  LogLevel,
  AggressivenessLevel,
  SensitivityLevel,
  ReportFormat,
  VerbosityLevel,
} from '../src/types/enums';

const BWAPP_URL = 'http://localhost:8080';

const bwappElementConfig: ElementScanConfig = {
  baseUrl: BWAPP_URL,
  pageUrl: '/sqli_1.php',
  elements: [
    {
      locator: 'input[name="title"]',
      name: 'Movie Title Search',
      description: 'bWAPP SQL Injection (GET/Search) input',
      type: AttackSurfaceType.FORM_INPUT,
      context: InjectionContext.SQL,
      testCategories: ['sqli'],
      metadata: {
        formAction: '/sqli_1.php',
        formMethod: 'GET',
      },
    },
  ],
  authentication: {
    loginUrl: '/login.php',
    loginActions: [
      { type: 'fill', selector: 'input[name="login"]', value: 'bee' },
      { type: 'fill', selector: 'input[name="password"]', value: 'bug' },
      { type: 'select', selector: 'select[name="security_level"]', value: '0' },
      { type: 'click', selector: 'button[name="form"]' },
    ],
    successIndicator: { type: 'url', value: 'portal.php' },
  },
  delayBetweenElements: 250,
  continueOnError: true,
};

async function runElementScan(): Promise<void> {
  const logger = new Logger(LogLevel.INFO, 'BwappElementScan');
  console.log('Starting bWAPP element scan...');

  let browser: Browser | null = null;

  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    const scanner = new ElementScanner(bwappElementConfig);
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
    ]);

    const scanContext = {
      page,
      browserContext: context,
      config: {
        target: { url: BWAPP_URL },
        scanners: {
          passive: { enabled: false },
          active: { enabled: true, aggressiveness: AggressivenessLevel.MEDIUM },
        },
        detectors: { enabled: ['sqli', 'xss'], sensitivity: SensitivityLevel.NORMAL },
        browser: { type: 'chromium' as const, headless: true },
        reporting: { formats: [ReportFormat.CONSOLE], outputDir: 'reports', verbosity: VerbosityLevel.NORMAL },
        advanced: { logLevel: LogLevel.INFO },
      },
      logger: logger.child('Scanner'),
      emitVulnerability: (vuln: unknown) => {
        const v = vuln as Vulnerability;
        console.log(`\n🔴 VULNERABILITY FOUND: ${v.title}`);
        console.log(`   URL: ${v.url}`);
        console.log(`   Severity: ${v.severity}`);
        console.log(`   Evidence: ${JSON.stringify(v.evidence).substring(0, 100)}...`);
      },
    };

    await scanner.initialize(scanContext);
    const result = await scanner.execute();

    console.log(`\nScan Complete. Vulnerabilities found: ${result.summary.total}`);

    if (result.summary.total > 0) {
      console.log('\nDetailed Findings:');
      result.vulnerabilities.forEach((v) => {
        console.log(`- [${v.severity}] ${v.title} on ${v.url}`);
      });
    }

    await scanner.cleanup();
  } catch (error) {
    console.error('Element scan failed:', error);
    throw error;
  } finally {
    if (browser) await browser.close();
  }
}

runElementScan().catch(console.error);
