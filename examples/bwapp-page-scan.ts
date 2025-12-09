/**
 * bWAPP Page Vulnerability Scan (targeted subset)
 *
 * Uses PageScanner with built-in bWAPP auth and shared page presets.
 *
 * Usage:
 *   BWAPP_URL=http://localhost:8080 npx tsx ./examples/bwapp-page-scan.ts
 */

import { chromium, Browser } from 'playwright';
import { PageScanner } from '../src/scanners/active/PageScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { PageScanConfig, PageTarget } from '../src/types/page-scan';
import { Vulnerability } from '../src/types/vulnerability';
import { Logger } from '../src/utils/logger/Logger';
import {
  LogLevel,
  AggressivenessLevel,
  SensitivityLevel,
  ReportFormat,
  VerbosityLevel,
} from '../src/types/enums';

const BWAPP_URL = process.env.BWAPP_URL ?? 'http://localhost:8080';

// Explicit pages for this demo run; tweak as needed per engagement scope
const targetPages: PageTarget[] = [
  { url: '/sqli_1.php', name: 'SQL Injection (GET/Search)' },
  { url: '/xss_get.php', name: 'XSS (Reflected GET)' },
  { url: '/commandi.php', name: 'OS Command Injection' },
];

const bwappConfig: PageScanConfig = {
  baseUrl: BWAPP_URL,
  bwappAuth: {
    username: process.env.BWAPP_USER ?? 'bee',
    password: process.env.BWAPP_PASSWORD ?? 'bug',
    securityLevel: process.env.BWAPP_SECURITY_LEVEL ?? '0',
  },
  pages: targetPages,
  pageTimeout: 30000,
  delayBetweenPages: 750,
  continueOnError: true,
};

async function runBwappScan(): Promise<void> {
  const logger = new Logger(LogLevel.INFO, 'BwappScan');
  console.log('Starting bWAPP scan (subset)...');

  let browser: Browser | null = null;

  try {
    browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    const scanner = new PageScanner(bwappConfig);
    scanner.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new InjectionDetector(),
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
        detectors: { enabled: ['sqli', 'xss', 'injection'], sensitivity: SensitivityLevel.NORMAL },
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
    console.error('Scan failed:', error);
    throw error;
  } finally {
    if (browser) await browser.close();
  }
}

runBwappScan().catch(console.error);
