import { test, expect } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';
import { PageScanner } from '../../src/scanners/active/PageScanner';
import { DomExplorer } from '../../src/scanners/active/DomExplorer';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { InjectionDetector } from '../../src/detectors/active/InjectionDetector';
import { PathTraversalDetector } from '../../src/detectors/active/PathTraversalDetector';
import { ErrorBasedDetector } from '../../src/detectors/active/ErrorBasedDetector';
import { SsrfDetector } from '../../src/detectors/active/SsrfDetector';
import { BolaDetector } from '../../src/detectors/active/BolaDetector';
import { Logger } from '../../src/utils/logger/Logger';
import { Vulnerability } from '../../src/types/vulnerability';
import { AggressivenessLevel, LogLevel, ReportFormat, SensitivityLevel, VerbosityLevel } from '../../src/types/enums';
import { ensureBwappAuthState } from '../../global-setup';

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';
const STORAGE_STATE = path.resolve(__dirname, '../../storage-states/bwapp-auth.json');
const LOG_DIR = path.resolve(__dirname, 'scan-logs');

const pages = [
  { url: '/sqli_1.php', name: 'SQLi GET/Search' },
  { url: '/xss_get.php', name: 'XSS GET' },
  { url: '/commandi.php', name: 'Command Injection' },
];

async function ensureDir(dir: string): Promise<void> {
  await fs.mkdir(dir, { recursive: true });
}

function makeLogger(): Logger {
  return new Logger(LogLevel.DEBUG, 'scanner-debug');
}

test.use({ storageState: STORAGE_STATE });

test.beforeAll(async () => {
  await ensureBwappAuthState(BASE_URL, STORAGE_STATE);
  await ensureDir(LOG_DIR);
});

test.describe('Scanner debug logging', () => {
  for (const pageTarget of pages) {
    test(`logs discovery, payloads, and verification for ${pageTarget.name}`, async ({ page, context }) => {
      const logLines: string[] = [];
      const logPath = path.join(LOG_DIR, `${pageTarget.url.replace(/\W+/g, '-')}.log`);

      const logger = makeLogger();
      const findings: Vulnerability[] = [];

      page.on('response', async (resp) => {
        if (resp.url().includes(pageTarget.url)) {
          const body = await resp.text().catch(() => '');
          logLines.push(`RESPONSE ${resp.status()} ${resp.url()}\n${body.slice(0, 500)}`);
        }
      });

      const explorer = new DomExplorer(LogLevel.DEBUG);
      await page.goto(`${BASE_URL}${pageTarget.url}`, { waitUntil: 'domcontentloaded' });
      const surfaces = await explorer.explore(page, []);
      logLines.push(`SURFACES ${JSON.stringify(surfaces.map((s) => ({ type: s.type, name: s.name, selector: s.selector, context: s.context, metadata: s.metadata })), null, 2)}`);

      const scanner = new PageScanner({
        baseUrl: BASE_URL,
        pages: [pageTarget],
        pageTimeout: 30000,
        continueOnError: true,
      });

      scanner.registerDetectors([
        new SqlInjectionDetector(),
        new XssDetector(),
        new InjectionDetector(),
        new PathTraversalDetector(),
        new ErrorBasedDetector(),
        new SsrfDetector(),
        new BolaDetector(),
      ]);

      const scanContext = {
        page,
        browserContext: context,
        config: {
          target: { url: BASE_URL },
          scanners: { active: { enabled: true, aggressiveness: AggressivenessLevel.MEDIUM } },
          detectors: { enabled: ['sqli', 'xss', 'injection'], sensitivity: SensitivityLevel.NORMAL },
          reporting: { formats: [ReportFormat.CONSOLE], outputDir: 'reports', verbosity: VerbosityLevel.DETAILED },
          advanced: { logLevel: LogLevel.DEBUG },
        },
        logger,
        emitVulnerability: (v: unknown) => {
          const vuln = v as Vulnerability;
          findings.push(vuln);
          logLines.push(`VULN ${vuln.title} CWE=${vuln.cwe} confidence=${vuln.confidence}`);
        },
      };

      await scanner.initialize(scanContext as any);
      const result = await scanner.execute();
      await scanner.cleanup();

      logLines.push(`SUMMARY total=${result.summary.total}`);
      await fs.writeFile(logPath, logLines.join('\n\n'), 'utf-8');

      expect(result.summary.total).toBeGreaterThan(0);
      expect(findings.length).toBeGreaterThan(0);
    });
  }
});
