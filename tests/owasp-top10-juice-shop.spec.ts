import { test, expect } from '@playwright/test';

import { DomExplorer } from '../src/scanners/active/DomExplorer';
import { LogLevel } from '../src/types/enums';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { ErrorBasedDetector } from '../src/detectors/active/ErrorBasedDetector';

const DEFAULT_JUICESHOP_URL = 'http://localhost:3000';

test.describe('Juice Shop OWASP Top 10 smoke', () => {
  test('runs core active detectors without crashing', async ({ page }) => {
    test.skip(process.env['RUN_JUICESHOP_TESTS'] !== '1', 'Set RUN_JUICESHOP_TESTS=1 to run Juice Shop integration tests');

    const baseUrl = process.env['JUICESHOP_URL'] || DEFAULT_JUICESHOP_URL;

    try {
      await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: 30_000 });
    } catch {
      test.skip(true, `Juice Shop not reachable at ${baseUrl}`);
    }

    await page.waitForLoadState('networkidle', { timeout: 10_000 }).catch(() => {});
    await expect(page).toHaveTitle(/Juice Shop/i);

    const domExplorer = new DomExplorer(LogLevel.ERROR);
    const surfaces = await domExplorer.explore(page, []);

    // Limit scope for smoke stability.
    const limited = surfaces.slice(0, 8);
    expect(limited.length).toBeGreaterThan(0);

    const detectors = [new SqlInjectionDetector(), new XssDetector(), new ErrorBasedDetector()];
    for (const detector of detectors) {
      await detector.validate().catch(() => {});
      const vulns = await detector.detect({ page, attackSurfaces: limited, baseUrl, safeMode: true });
      expect(Array.isArray(vulns)).toBeTruthy();
    }
  });
});
