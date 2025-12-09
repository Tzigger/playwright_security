/**
 * bWAPP Comprehensive Page Scan
 *
 * Scans a set of bWAPP vulnerability pages (OWASP Top 10 style) using the PageScanner
 * with built-in bWAPP authentication (bee/bug) and preset page targets.
 *
 * Usage:
 *   BWAPP_URL=http://localhost:8080 npx tsx ./examples/bwapp-comprehensive-scan.ts
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

const bwappPages: PageTarget[] = [
  { url: '/sqli_1.php', name: 'SQL Injection (GET/Search)' },
  { url: '/sqli_10-1.php', name: 'SQL Injection (AJAX/JSON)' },
  { url: '/xss_get.php', name: 'XSS (Reflected GET)' },
  { url: '/xss_post.php', name: 'XSS (Reflected POST)' },
  { url: '/commandi.php', name: 'OS Command Injection' },
  { url: '/login.php', name: 'Login Form (Broken Auth)' },
  { url: '/csrf_1.php', name: 'CSRF (Change Password)' },
  { url: '/ssrf_1.php', name: 'SSRF' },
  { url: '/cors_1.php', name: 'CORS Misconfiguration' },
  { url: '/unvalidated_redirect_1.php', name: 'Unvalidated Redirect' },
  { url: '/directory_traversal_1.php', name: 'Directory Traversal' },
  { url: '/idor_1.php', name: 'IDOR' },
];

const bwappConfig: PageScanConfig = {
  baseUrl: BWAPP_URL,
  bwappAuth: {
    username: process.env.BWAPP_USER ?? 'bee',
    password: process.env.BWAPP_PASSWORD ?? 'bug',
    securityLevel: process.env.BWAPP_SECURITY_LEVEL ?? '0',
    loginUrl: '/login.php',
    portalPath: '/portal.php',
  },
  pages: bwappPages,
  pageTimeout: 30000,
  delayBetweenPages: 750,
  continueOnError: true,
};

async function runBwappComprehensiveScan(): Promise<void> {
  const logger = new Logger(LogLevel.INFO, 'BwappComprehensiveScan');
  console.log('Starting comprehensive bWAPP scan...');

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
        detectors: {
          enabled: ['sqli', 'xss', 'injection'],
          sensitivity: SensitivityLevel.NORMAL,
        },
        browser: { type: 'chromium' as const, headless: true },
        reporting: {
          formats: [ReportFormat.CONSOLE],
          outputDir: 'reports',
          verbosity: VerbosityLevel.NORMAL,
        },
        advanced: { logLevel: LogLevel.INFO },
      },
      logger: logger.child('Scanner'),
      emitVulnerability: (vuln: unknown) => {
        const v = vuln as Vulnerability;
        console.log(`\n🔴 VULNERABILITY FOUND: ${v.title}`);
        console.log(`   URL: ${v.url}`);
        console.log(`   Severity: ${v.severity}`);
        console.log(`   Evidence: ${JSON.stringify(v.evidence).substring(0, 150)}...`);
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

runBwappComprehensiveScan().catch(console.error);
