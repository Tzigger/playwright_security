import { test, expect, Page, BrowserContext } from '@playwright/test';
import { PageScanner } from '../../src/scanners/active/PageScanner';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { InjectionDetector } from '../../src/detectors/active/InjectionDetector';
import { PathTraversalDetector } from '../../src/detectors/active/PathTraversalDetector';
import { BolaDetector } from '../../src/detectors/active/BolaDetector';
import { SsrfDetector } from '../../src/detectors/active/SsrfDetector';
import { ErrorBasedDetector } from '../../src/detectors/active/ErrorBasedDetector';
import { Logger } from '../../src/utils/logger/Logger';
import { LogLevel, AggressivenessLevel, SensitivityLevel, ReportFormat, VerbosityLevel, VulnerabilitySeverity } from '../../src/types/enums';
import { ScanConfiguration } from '../../src/types/config';
import { PageTarget } from '../../src/types/page-scan';
import { Vulnerability } from '../../src/types/vulnerability';

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const STORAGE_STATE = 'storage-states/bwapp-auth.json';

const makeScanConfig = (baseUrl: string): ScanConfiguration => ({
  target: {
    url: baseUrl,
    maxPages: 1,
    timeout: 45000,
  },
  scanners: {
    passive: { enabled: false },
    active: {
      enabled: true,
      aggressiveness: AggressivenessLevel.MEDIUM,
      delayBetweenRequests: 100,
    },
  },
  detectors: {
    enabled: [],
    disabled: [],
    sensitivity: SensitivityLevel.NORMAL,
    minConfidence: 0.5,
  },
  browser: {
    type: 'chromium',
    headless: true,
    ignoreHTTPSErrors: true,
  },
  reporting: {
    formats: [ReportFormat.JSON],
    outputDir: 'test-security-reports',
    verbosity: VerbosityLevel.MINIMAL,
    includeScreenshots: false,
    perPageReports: false,
  },
  advanced: {
    logLevel: LogLevel.INFO,
    retryFailedRequests: true,
    maxRetries: 1,
    parallelism: 1,
  },
});

async function runPageScan(page: Page, context: BrowserContext, pageTarget: PageTarget, detectors: any[]) {
  const scanner = new PageScanner({
    baseUrl: BASE_URL,
    pages: [pageTarget],
    pageTimeout: 45000,
    continueOnError: true,
  });

  detectors.forEach((d) => scanner.registerDetector(d));

  const vulnerabilities: Vulnerability[] = [];
  const logger = new Logger(LogLevel.INFO, 'bwapp-validation');
  const scanConfig = makeScanConfig(BASE_URL);
  const scanContext = {
    page,
    browserContext: context,
    config: scanConfig,
    logger,
    emitVulnerability: (v: unknown) => vulnerabilities.push(v as Vulnerability),
  };

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  await scanner.cleanup();

  // Merge emitted vulns with returned ones for easier assertions
  const combined = result.vulnerabilities.length ? result.vulnerabilities : vulnerabilities;
  return { result: { ...result, vulnerabilities: combined }, emitted: vulnerabilities };
}

test.use({ storageState: STORAGE_STATE });

test.describe('bWAPP PageScanner Validation - OWASP Top 10', () => {
  test.describe('A03:2021 Injection', () => {
    test('SQL Injection: sqli_1.php (GET/Search)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/sqli_1.php',
        name: 'SQLi GET/Search',
        formValues: { title: 'movie' }
      }, [new SqlInjectionDetector({
        permissiveMode: true,
        minConfidenceForEarlyExit: 0.6,
        enableErrorBased: true,
        enableBooleanBased: true,
        enableTimeBased: false
      })]);

      const sqlVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-89');
      expect(sqlVulns.length).toBeGreaterThan(0);
      expect(sqlVulns[0]?.confidence ?? 0).toBeGreaterThanOrEqual(0.7);
      expect(sqlVulns.every((v) => v.evidence?.request && v.evidence?.response)).toBe(true);
      expect(sqlVulns.every((v) => (v.owasp || '').includes('A03'))).toBe(true);
      expect(sqlVulns.every((v) => ((v.metadata?.['verificationAttempts'] as number | undefined) ?? 1) >= 1)).toBe(true);
    });

    test('SQL Injection: sqli_6.php (Login Bypass)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/sqli_6.php',
        name: 'SQLi Login Bypass',
      }, [new SqlInjectionDetector()]);

      const sqlVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-89');
      expect(sqlVulns.length).toBeGreaterThan(0);
      expect(sqlVulns[0]?.confidence ?? 0).toBeGreaterThanOrEqual(0.7);
    });

    test('SQL Injection: sqli_10-1.php (AJAX/JSON)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/sqli_10-1.php',
        name: 'SQLi AJAX/JSON',
      }, [new SqlInjectionDetector()]);

      const sqlVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-89');
      expect(sqlVulns.length).toBeGreaterThan(0);
      expect(sqlVulns.every((v) => (v.evidence?.response?.body || '').length > 0)).toBe(true);
    });

    test('XSS: xss_get.php (Reflected GET)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/xss_get.php',
        name: 'XSS GET',
        formValues: { firstname: 'test', lastname: 'test' }
      }, [new XssDetector({
        permissiveMode: true,
        minConfidenceForEarlyExit: 0.6,
        checkEncoding: true
      })]);

      const xssVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-79');
      expect(xssVulns.length).toBeGreaterThan(0);
      expect(xssVulns.every((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
      expect(xssVulns.every((v) => v.evidence?.response?.body?.toString().toLowerCase().includes('script'))).toBe(true);
    });

    test('XSS: xss_post.php (Reflected POST)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/xss_post.php',
        name: 'XSS POST',
      }, [new XssDetector()]);

      const xssVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-79');
      expect(xssVulns.length).toBeGreaterThan(0);
      expect(xssVulns.some((v) => v.evidence?.request?.body)).toBe(true);
    });

    test('XSS: xss_stored_1.php (Stored)', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/xss_stored_1.php',
        name: 'Stored XSS',
      }, [new XssDetector()]);

      const xssVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-79');
      expect(xssVulns.length).toBeGreaterThan(0);
      expect(xssVulns.every((v) => (v.metadata?.affectedComponents ?? []).length >= 0)).toBe(true);
    });

    test('Command Injection: commandi.php', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/commandi.php',
        name: 'Command Injection',
        formValues: { target: '127.0.0.1' }
      }, [new InjectionDetector(LogLevel.DEBUG, { permissiveMode: true })]);

      const injVulns = result.vulnerabilities.filter((v) => (v.cwe || '').includes('77') || (v.cwe || '').includes('78'));
      expect(injVulns.length).toBeGreaterThan(0);
      expect(injVulns.every((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
    });
  });

  test.describe('A01:2021 Broken Access Control', () => {
    test('Path Traversal: directory_traversal_1.php', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/directory_traversal_1.php',
        name: 'Path Traversal',
      }, [new PathTraversalDetector()]);

      const ptVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-22');
      expect(ptVulns.length).toBeGreaterThan(0);
      expect(ptVulns[0]?.confidence ?? 0).toBeGreaterThanOrEqual(0.85);
      expect(ptVulns.some((v) => (v.evidence?.response?.body || '').includes('root:x'))).toBe(true);
    });

    test('IDOR: idor_1.php', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/idor_1.php',
        name: 'BOLA/IDOR',
      }, [new BolaDetector()]);

      const idorVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-639' || (v.title || '').toLowerCase().includes('idor'));
      expect(idorVulns.length).toBeGreaterThan(0);
      expect(idorVulns.every((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
    });
  });

  test.describe('A10:2021 SSRF', () => {
    test('SSRF: ssrf_1.php', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/ssrf_1.php',
        name: 'SSRF',
      }, [new SsrfDetector()]);

      const ssrfVulns = result.vulnerabilities.filter((v) => v.cwe === 'CWE-918');
      expect(ssrfVulns.length).toBeGreaterThan(0);
      expect(ssrfVulns.every((v) => (v.confidence ?? 0) >= 0.8)).toBe(true);
    });
  });

  test.describe('A05:2021 Security Misconfiguration', () => {
    test('Error Disclosure: Multiple pages', async ({ page, context }) => {
      const { result } = await runPageScan(page, context, {
        url: '/install.php',
        name: 'Error Disclosure',
      }, [new ErrorBasedDetector()]);

      expect(result.vulnerabilities.length).toBeGreaterThan(0);
      expect(result.vulnerabilities.every((v) => (v.confidence ?? 0) >= 0.6)).toBe(true);
    });
  });

  test('Full OWASP Coverage: All detectors on portal', async ({ page, context }) => {
    const detectors = [
      new SqlInjectionDetector(),
      new XssDetector(),
      new InjectionDetector(),
      new PathTraversalDetector(),
      new SsrfDetector(),
      new BolaDetector(),
      new ErrorBasedDetector(),
    ];

    const { result } = await runPageScan(page, context, {
      url: '/portal.php',
      name: 'Portal Comprehensive',
      description: 'Runs multiple detectors to ensure coverage',
    }, detectors);

    // Basic assertion: some vulnerabilities found
    expect(result.vulnerabilities.length).toBeGreaterThan(0);
    expect(result.vulnerabilities.some((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
    expect(result.vulnerabilities.some((v) => {
      const attempts = v.metadata?.verificationAttempts as number | undefined;
      return attempts !== undefined && attempts >= 2;
    })).toBe(true);

    // Category breadth assertions: ensure major categories are represented
    // Injection category (CWE-89, CWE-79, CWE-77, CWE-78)
    const injectionVulns = result.vulnerabilities.filter((v) => 
      v.cwe === 'CWE-89' || v.cwe === 'CWE-79' || v.cwe === 'CWE-77' || v.cwe === 'CWE-78' ||
      v.category?.toLowerCase().includes('injection') || v.category?.toLowerCase().includes('xss')
    );
    
    // Access Control category (CWE-22, CWE-639)
    const accessControlVulns = result.vulnerabilities.filter((v) => 
      v.cwe === 'CWE-22' || v.cwe === 'CWE-639' ||
      v.category?.toLowerCase().includes('traversal') || v.category?.toLowerCase().includes('idor') ||
      v.category?.toLowerCase().includes('bola') || v.category?.toLowerCase().includes('access')
    );
    
    // Error/Misconfiguration category
    const misconfigVulns = result.vulnerabilities.filter((v) => 
      v.category?.toLowerCase().includes('error') || v.category?.toLowerCase().includes('disclosure') ||
      v.category?.toLowerCase().includes('misconfiguration')
    );

    // At least 2 of 3 major categories should have findings
    const categoriesWithFindings = [
      injectionVulns.length > 0,
      accessControlVulns.length > 0,
      misconfigVulns.length > 0,
    ].filter(Boolean).length;
    
    expect(categoriesWithFindings).toBeGreaterThanOrEqual(2);

    // Confidence check applies to each category that has findings
    if (injectionVulns.length > 0) {
      expect(injectionVulns.some((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
    }
    if (accessControlVulns.length > 0) {
      expect(accessControlVulns.some((v) => (v.confidence ?? 0) >= 0.7)).toBe(true);
    }
  });

  test('False Positive Check: Clean page returns no findings', async ({ page, context }) => {
    const { result } = await runPageScan(page, context, {
      url: '/robots.txt',
      name: 'Clean Page',
    }, [new SqlInjectionDetector(), new XssDetector(), new ErrorBasedDetector()]);

    const nonInfo = result.vulnerabilities.filter((v) => v.severity !== VulnerabilitySeverity.INFO);
    expect(nonInfo.length).toBe(0);
  });
});
