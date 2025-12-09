import { test, expect } from '@playwright/test';
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

const BWAPP_URL = process.env.BWAPP_URL ?? 'http://localhost:8080';

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
      { type: 'fill', selector: 'input[name="login"]', value: process.env.BWAPP_USER ?? 'bee' },
      { type: 'fill', selector: 'input[name="password"]', value: process.env.BWAPP_PASSWORD ?? 'bug' },
      { type: 'select', selector: 'select[name="security_level"]', value: process.env.BWAPP_SECURITY_LEVEL ?? '0' },
      { type: 'click', selector: 'button[name="form"]' },
    ],
    successIndicator: { type: 'url', value: 'portal.php' },
  },
  delayBetweenElements: 250,
  continueOnError: true,
};

test.use({ storageState: 'storage-states/bwapp-auth.json' });

test.describe('bWAPP element scanner', () => {
  test('detects SQL injection on movie search', async ({ page, context }) => {
    test.setTimeout(120000);

    const logger = new Logger(LogLevel.INFO, 'BwappElementScanSpec');
    const findings: Vulnerability[] = [];

    const scanner = new ElementScanner(bwappElementConfig);
    scanner.registerDetectors([new SqlInjectionDetector(), new XssDetector()]);

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
          enabled: ['sqli', 'xss'],
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
        findings.push(v);
        logger.info(`Detected ${v.title}`);
      },
    };

    await scanner.initialize(scanContext);
    const result = await scanner.execute();
    await scanner.cleanup();

    const sqlFindings = findings.filter((v) => v.category === 'injection' || v.title.toLowerCase().includes('sql'));

    console.log(`Scan Complete. Vulnerabilities found: ${result.summary.total}`);
    sqlFindings.slice(0, 5).forEach((v) => console.log(`- [${v.severity}] ${v.title} (${v.url})`));

    expect(sqlFindings.length).toBeGreaterThan(0);
  });
});
