import { chromium } from 'playwright';
import fs from 'fs/promises';
import path from 'path';
import { ensureBwappAuthState } from '../global-setup';
import { PageScanner } from '../src/scanners/active/PageScanner';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { PathTraversalDetector } from '../src/detectors/active/PathTraversalDetector';
import { BolaDetector } from '../src/detectors/active/BolaDetector';
import { SsrfDetector } from '../src/detectors/active/SsrfDetector';
import { ErrorBasedDetector } from '../src/detectors/active/ErrorBasedDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel, AggressivenessLevel, SensitivityLevel, ReportFormat, VerbosityLevel } from '../src/types/enums';
import { ScanConfiguration } from '../src/types/config';
import { PageTarget } from '../src/types/page-scan';

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const STORAGE_STATE = path.join(__dirname, '..', 'storage-states', 'bwapp-auth.json');
const REPORT_DIR = path.join(__dirname, '..', 'test-security-reports');

const makeScanConfig = (baseUrl: string): ScanConfiguration => ({
  target: { url: baseUrl, maxPages: 1, timeout: 45000 },
  scanners: {
    passive: { enabled: false },
    active: { enabled: true, aggressiveness: AggressivenessLevel.MEDIUM, delayBetweenRequests: 100 },
  },
  detectors: {
    enabled: [],
    disabled: [],
    sensitivity: SensitivityLevel.NORMAL,
    minConfidence: 0.5,
  },
  browser: { type: 'chromium', headless: true, ignoreHTTPSErrors: true },
  reporting: { formats: [ReportFormat.JSON], outputDir: REPORT_DIR, verbosity: VerbosityLevel.MINIMAL },
  advanced: { logLevel: LogLevel.INFO, retryFailedRequests: true, maxRetries: 1, parallelism: 1 },
});

async function runScenario(name: string, pages: PageTarget[]) {
  const browser = await chromium.launch({ headless: true });
  const storageState = await ensureBwappAuthState(BASE_URL, STORAGE_STATE);
  const context = await browser.newContext({ storageState, baseURL: BASE_URL });
  const page = await context.newPage();
  const logger = new Logger(LogLevel.INFO, `bwapp-${name}`);
  const scanner = new PageScanner({ baseUrl: BASE_URL, pages, pageTimeout: 45000, continueOnError: true });

  const detectors = [
    new SqlInjectionDetector(),
    new XssDetector(),
    new InjectionDetector(),
    new PathTraversalDetector(),
    new SsrfDetector(),
    new BolaDetector(),
    new ErrorBasedDetector(),
  ];
  detectors.forEach((d) => scanner.registerDetector(d));

  await fs.mkdir(REPORT_DIR, { recursive: true });

  const scanContext = {
    page,
    browserContext: context,
    config: makeScanConfig(BASE_URL),
    logger,
  };

  await scanner.initialize(scanContext);
  const result = await scanner.execute();
  await scanner.cleanup();
  await context.close();
  await browser.close();

  const summary = result.vulnerabilities.map((v) => ({
    title: v.title,
    cwe: v.cwe,
    owasp: v.owasp,
    severity: v.severity,
    confidence: v.confidence,
    url: v.url,
    evidence: {
      request: v.evidence?.request,
      responseSnippet: v.evidence?.response?.body?.toString()?.slice(0, 200),
    },
  }));

  const jsonPath = path.join(REPORT_DIR, 'bwapp-page-validation.json');
  await fs.writeFile(jsonPath, JSON.stringify(summary, null, 2), 'utf-8');

  const htmlRows = summary
    .map((v) => `<tr><td>${v.title}</td><td>${v.cwe || ''}</td><td>${v.owasp || ''}</td><td>${v.severity}</td><td>${(v.confidence ?? 0).toFixed(2)}</td><td>${v.url || ''}</td></tr>`)
    .join('');
  const html = `<!doctype html><html><head><meta charset="utf-8"><title>bWAPP Validation</title></head><body><h1>bWAPP Validation - ${name}</h1><table border="1" cellspacing="0" cellpadding="4"><thead><tr><th>Title</th><th>CWE</th><th>OWASP</th><th>Severity</th><th>Confidence</th><th>URL</th></tr></thead><tbody>${htmlRows}</tbody></table></body></html>`;
  const htmlPath = path.join(REPORT_DIR, 'bwapp-page-validation.html');
  await fs.writeFile(htmlPath, html, 'utf-8');

  console.log(`Scenario "${name}" complete. Findings: ${summary.length}`);
  summary.forEach((v) => console.log(`- ${v.title} [${v.severity}] conf=${v.confidence ?? 0}`));
}

(async () => {
  const pages: PageTarget[] = [
    { url: '/sqli_1.php', name: 'SQLi GET/Search' },
    { url: '/sqli_6.php', name: 'SQLi Login' },
    { url: '/sqli_10-1.php', name: 'SQLi AJAX' },
    { url: '/xss_get.php', name: 'XSS GET' },
    { url: '/xss_post.php', name: 'XSS POST' },
    { url: '/xss_stored_1.php', name: 'Stored XSS' },
    { url: '/commandi.php', name: 'Command Injection' },
    { url: '/directory_traversal_1.php', name: 'Path Traversal' },
    { url: '/idor_1.php', name: 'IDOR' },
    { url: '/ssrf_1.php', name: 'SSRF' },
    { url: '/install.php', name: 'Error Disclosure' },
  ];

  await runScenario('owasp-top10', pages);
})().catch((err) => {
  console.error('bWAPP validation failed', err);
  process.exit(1);
});
