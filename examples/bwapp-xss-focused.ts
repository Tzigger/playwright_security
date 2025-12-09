import { chromium } from 'playwright';
import path from 'path';
import { ensureBwappAuthState } from '../global-setup';
import { PageScanner } from '../src/scanners/active/PageScanner';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel, AggressivenessLevel, SensitivityLevel, ReportFormat, VerbosityLevel } from '../src/types/enums';
import { ScanConfiguration } from '../src/types/config';
import { PageTarget } from '../src/types/page-scan';

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const STORAGE_STATE = path.join(__dirname, '..', 'storage-states', 'bwapp-auth.json');

const makeScanConfig = (baseUrl: string): ScanConfiguration => ({
  target: { url: baseUrl, maxPages: 1, timeout: 45000 },
  scanners: { passive: { enabled: false }, active: { enabled: true, aggressiveness: AggressivenessLevel.MEDIUM } },
  detectors: { enabled: [], disabled: [], sensitivity: SensitivityLevel.NORMAL, minConfidence: 0.5 },
  browser: { type: 'chromium', headless: true, ignoreHTTPSErrors: true },
  reporting: { formats: [ReportFormat.JSON], outputDir: 'test-security-reports', verbosity: VerbosityLevel.MINIMAL },
  advanced: { logLevel: LogLevel.INFO, retryFailedRequests: true, maxRetries: 1, parallelism: 1 },
});

async function runXssScenario(pages: PageTarget[]) {
  const browser = await chromium.launch({ headless: true });
  const storageState = await ensureBwappAuthState(BASE_URL, STORAGE_STATE);
  const context = await browser.newContext({ storageState, baseURL: BASE_URL });
  const page = await context.newPage();
  const logger = new Logger(LogLevel.INFO, 'bwapp-xss');
  const scanner = new PageScanner({ baseUrl: BASE_URL, pages, pageTimeout: 45000, continueOnError: true });
  scanner.registerDetector(new XssDetector());

  await scanner.initialize({ page, browserContext: context, config: makeScanConfig(BASE_URL), logger });
  const result = await scanner.execute();
  await scanner.cleanup();
  await context.close();
  await browser.close();

  console.log(`XSS focused scan complete. Findings: ${result.vulnerabilities.length}`);
  result.vulnerabilities.forEach((v) => {
    console.log(`- ${v.title} (CWE: ${v.cwe || ''}) conf=${v.confidence ?? 0}`);
  });
}

(async () => {
  const pages: PageTarget[] = [
    { url: '/xss_get.php', name: 'Reflected XSS GET' },
    { url: '/xss_post.php', name: 'Reflected XSS POST' },
    { url: '/xss_stored_1.php', name: 'Stored XSS' },
  ];

  await runXssScenario(pages);
})().catch((err) => {
  console.error('XSS focused scan failed', err);
  process.exit(1);
});
