import { test, expect } from '@playwright/test';

import { DomExplorer } from '../src/scanners/active/DomExplorer';
import { LogLevel } from '../src/types/enums';
import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';

const DEFAULT_JUICESHOP_URL = 'http://localhost:3000';

test.describe('Juice Shop SQLi smoke', () => {
  test('runs SqlInjectionDetector on discovered surfaces', async ({ page }) => {
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

    const targets = domExplorer.getSqlInjectionTargets(surfaces).slice(0, 5);
    expect(targets.length).toBeGreaterThan(0);

    const detector = new SqlInjectionDetector();
    await detector.validate().catch(() => {});

    const vulns = await detector.detect({ page, attackSurfaces: targets, baseUrl, safeMode: true });
    expect(Array.isArray(vulns)).toBeTruthy();

    // If findings exist, payload should be present for reproducibility.
    for (const v of vulns) {
      expect(typeof v.title).toBe('string');
      if (v.evidence?.payload) {
        expect(v.evidence.payload.length).toBeGreaterThan(0);
      }
    }
  });
});
