import { test, expect } from '@playwright/test';
import { PageScanner } from '../src/scanners/active/PageScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { PageScanConfig, PageTarget } from '../src/types/page-scan';
import { Vulnerability } from '../src/types/vulnerability';
import {
  LogLevel,
  AggressivenessLevel,
  SensitivityLevel,
  ReportFormat,
  VerbosityLevel,
} from '../src/types/enums';
import { Logger } from '../src/utils/logger/Logger';

const BWAPP_URL = process.env.BWAPP_URL ?? 'http://localhost:8080';

const bwappPages: PageTarget[] = [
  { url: '/sqli_1.php', name: 'SQL Injection (GET/Search)' },
  { url: '/sqli_10-1.php', name: 'SQL Injection (AJAX/JSON)' },
  { url: '/xss_get.php', name: 'XSS (Reflected GET)' },
  { url: '/xss_post.php', name: 'XSS (Reflected POST)' },
  { url: '/commandi.php', name: 'OS Command Injection' },
];

const bwappConfig: PageScanConfig = {
  baseUrl: BWAPP_URL,
  bwappAuth: {
    username: process.env.BWAPP_USER ?? 'bee',
    password: process.env.BWAPP_PASSWORD ?? 'bug',
    securityLevel: process.env.BWAPP_SECURITY_LEVEL ?? '0',
  },
  pages: bwappPages,
  pageTimeout: 20000,
  delayBetweenPages: 500,
  continueOnError: true,
};

test.describe('bWAPP PageScanner comprehensive', () => {
  test('covers OWASP-style pages for common vulns', async ({ page, context }) => {
    test.setTimeout(180000);

    const logger = new Logger(LogLevel.DEBUG, 'BwappComprehensiveSpec');
    const findings: Vulnerability[] = [];

    const scanner = new PageScanner(bwappConfig, LogLevel.DEBUG);
    
    // Create detectors with DEBUG level
    const sqliDetector = new SqlInjectionDetector();
    const xssDetector = new XssDetector();
    const injectionDetector = new InjectionDetector(LogLevel.DEBUG);
    
    logger.info(`Registering detectors: ${sqliDetector.name}, ${xssDetector.name}, ${injectionDetector.name}`);
    scanner.registerDetectors([sqliDetector, xssDetector, injectionDetector]);

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
        advanced: { logLevel: LogLevel.DEBUG },
      },
      logger: logger.child('Scanner'),
      emitVulnerability: (vuln: unknown) => {
        const v = vuln as Vulnerability;
        findings.push(v);
        logger.info(`Detected ${v.title}`);
      },
    };

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    await scanner.cleanup();

    // Basic assertion: some vulnerabilities found
    expect(result.summary.total).toBeGreaterThan(0);
    expect(findings.length).toBeGreaterThan(0);

    // Page-specific assertions to ensure detectors are working on target pages
    const allVulns = [...result.vulnerabilities, ...findings];

    // SQL Injection check for /sqli_1.php
    const sqliPageVulns = allVulns.filter(v => 
      v.url?.includes('sqli_1.php') || v.evidence?.request?.url?.includes('sqli_1.php')
    );
    const sqliCweVulns = sqliPageVulns.filter(v => v.cwe === 'CWE-89');
    expect(sqliCweVulns.length).toBeGreaterThan(0);
    expect(sqliCweVulns.some(v => v.evidence && (v.evidence.request || v.evidence.response))).toBe(true);

    // XSS check for /xss_get.php
    const xssGetPageVulns = allVulns.filter(v => 
      v.url?.includes('xss_get.php') || v.evidence?.request?.url?.includes('xss_get.php')
    );
    const xssGetCweVulns = xssGetPageVulns.filter(v => v.cwe === 'CWE-79');
    expect(xssGetCweVulns.length).toBeGreaterThan(0);
    expect(xssGetCweVulns.some(v => 
      v.evidence?.response?.body?.toString().toLowerCase().includes('script') ||
      v.evidence?.requestBody?.toLowerCase().includes('script')
    )).toBe(true);

    // XSS check for /xss_post.php
    const xssPostPageVulns = allVulns.filter(v => 
      v.url?.includes('xss_post.php') || v.evidence?.request?.url?.includes('xss_post.php')
    );
    const xssPostCweVulns = xssPostPageVulns.filter(v => v.cwe === 'CWE-79');
    expect(xssPostCweVulns.length).toBeGreaterThan(0);
    expect(xssPostCweVulns.some(v => 
      v.evidence?.response?.body?.toString().toLowerCase().includes('script') ||
      v.evidence?.requestBody?.toLowerCase().includes('script')
    )).toBe(true);

    // Command Injection check for /commandi.php
    const commandiPageVulns = allVulns.filter(v => 
      v.url?.includes('commandi.php') || v.evidence?.request?.url?.includes('commandi.php')
    );
    const commandiCweVulns = commandiPageVulns.filter(v => 
      v.cwe === 'CWE-77' || v.cwe === 'CWE-78'
    );
    expect(commandiCweVulns.length).toBeGreaterThan(0);
  });
});
