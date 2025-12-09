/**
 * bWAPP Active Scan (Crawl + Scan)
 *
 * Tests the ActiveScanner on a specific bWAPP page with authentication.
 *
 * Usage:
 *   npx ts-node examples/bwapp-active-scan.ts
 */

import { chromium, Browser, Page } from 'playwright';
import { ActiveScanner } from '../src/scanners/active/ActiveScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { ScanContext } from '../src/core/interfaces/IScanner';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel, ReportFormat, VerbosityLevel, AggressivenessLevel, SensitivityLevel } from '../src/types/enums';
import { Vulnerability } from '../src/types/vulnerability';

const BWAPP_URL = 'http://localhost:8080';
const TARGET_PAGE = `${BWAPP_URL}/sqli_1.php`;

async function runActiveScan(): Promise<void> {
  const logger = new Logger(LogLevel.INFO, 'ActiveScanTest');
  console.log('Starting bWAPP Active Scanner Test...');

  let browser: Browser | null = null;

  try {
    // 1. Launch & Login
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    console.log('Logging in...');
    await page.goto(`${BWAPP_URL}/login.php`);
    await page.fill('input[name="login"]', 'bee');
    await page.fill('input[name="password"]', 'bug');
    await page.selectOption('select[name="security_level"]', '0'); // Low security
    await page.click('button[name="form"]');
    await page.waitForLoadState('networkidle');

    if (!page.url().includes('portal.php')) {
      console.error('Login failed! Current URL:', page.url());
      return;
    }
    console.log('Login successful.');

    // 2. Navigate to Target (optional, scanner should do it, but good for priming)
    await page.goto(TARGET_PAGE);
    console.log(`Navigated to target: ${TARGET_PAGE}`);

    // 3. Initialize ActiveScanner
    const scanner = new ActiveScanner({
      maxDepth: 1, // Restrict crawling for this test
      maxPages: 3,
      aggressiveness: 'medium',
    });

    // Register Detectors
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new InjectionDetector(),
    ]);

    // 4. Create Context
    const scanContext: ScanContext = {
      page,
      browserContext: context,
      config: {
        target: { 
          url: TARGET_PAGE, 
          maxPages: 3, 
          crawlDepth: 1 
        },
        scanners: {
          passive: { enabled: false },
          active: { 
            enabled: true,
            aggressiveness: AggressivenessLevel.MEDIUM
          },
        },
        detectors: {
          enabled: ['sqli', 'xss', 'injection'],
          sensitivity: SensitivityLevel.NORMAL
        },
        browser: {
          headless: true,
          type: 'chromium'
        },
        reporting: {
          formats: [ReportFormat.CONSOLE],
          outputDir: 'reports',
          verbosity: VerbosityLevel.NORMAL
        },
        advanced: {
          logLevel: LogLevel.INFO
        }
      },
      logger: logger.child('Scanner'),
      emitVulnerability: (vuln: unknown) => {
         const v = vuln as Vulnerability;
         console.log(`\n🔴 VULNERABILITY FOUND: ${v.title}`);
         console.log(`   URL: ${v.url}`);
         console.log(`   Severity: ${v.severity}`);
      },
    };

    // 5. Execute Scan
    await scanner.initialize(scanContext);
    console.log('\nStarting Scanner Execution...');
    const result = await scanner.execute();

    console.log(`\nScan Complete. Vulnerabilities found: ${result.summary.total}`);
    
    if (result.summary.total > 0) {
      console.log('\nDetailed Findings:');
      result.vulnerabilities.forEach(v => {
        console.log(`- [${v.severity}] ${v.title}`);
      });
    }

    await scanner.cleanup();

  } catch (error) {
    console.error('Test failed:', error);
  } finally {
    if (browser) await browser.close();
  }
}

runActiveScan().catch(console.error);
