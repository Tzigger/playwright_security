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

// Minimal subset for fast feedback; comprehensive suite lives in bwapp-comprehensive-scan.spec.ts
const targetPages: PageTarget[] = [
  { url: '/sqli_1.php', name: 'SQL Injection (GET/Search)' },
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

test.describe('bWAPP PageScanner subset', () => {
  test('scans key pages for SQLi/XSS', async ({ page, context }) => {
    test.setTimeout(90000);

    const logger = new Logger(LogLevel.INFO, 'BwappPageScanSpec');
    const findings: Vulnerability[] = [];

    const scanner = new PageScanner(bwappConfig);

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
        findings.push(v);
        logger.info(`Detected ${v.title}`);
      },
    };

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    await scanner.cleanup();

    // Smoke assertion: scanner completes without detectors configured
    expect(result.summary.total).toBe(0);
    expect(findings.length).toBe(0);
  });
});
