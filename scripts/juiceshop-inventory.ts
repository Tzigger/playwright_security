import { chromium } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

import { DomExplorer, AttackSurface } from '../src/scanners/active/DomExplorer';
import { LogLevel } from '../src/types/enums';
import { Logger } from '../src/utils/logger/Logger';

type SerializableAttackSurface = Omit<AttackSurface, 'element'> & {
  element?: undefined;
};

const DEFAULT_JUICESHOP_URL = 'http://localhost:3000';
const OUTPUT_PATH = path.join(process.cwd(), 'test-security-reports', 'juiceshop-surfaces.json');

function makeLogger(): Logger {
  return new Logger(LogLevel.INFO, 'juiceshop-inventory');
}

function stableSurfaceKey(surface: AttackSurface): string {
  const url = surface.metadata?.['url'] ? String(surface.metadata['url']) : '';
  const method = surface.metadata?.['method'] ? String(surface.metadata['method']).toUpperCase() : '';
  const parameterName = surface.metadata?.['parameterName'] ? String(surface.metadata['parameterName']) : '';
  const originalKey = surface.metadata?.['originalKey'] ? String(surface.metadata['originalKey']) : '';
  return [surface.type, surface.name, surface.context, method, url, parameterName, originalKey, surface.selector || ''].join('|');
}

function toSerializable(surface: AttackSurface): SerializableAttackSurface {
  const { element: _element, ...rest } = surface;
  return rest;
}

async function exploreSingleUrl(args: {
  pageUrl: string;
  domExplorer: DomExplorer;
  logger: Logger;
  maxWaitMs: number;
}): Promise<AttackSurface[]> {
  const { pageUrl, domExplorer, logger, maxWaitMs } = args;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const capturedRequests: any[] = [];
  const requestListener = (request: any) => {
    const resourceType = request.resourceType?.();
    if (['xhr', 'fetch', 'document'].includes(resourceType)) {
      capturedRequests.push(request);
    }
  };

  domExplorer.clearDynamicSurfaces();
  domExplorer.startMonitoring(page);
  page.on('request', requestListener);

  try {
    await page.goto(pageUrl, { waitUntil: 'domcontentloaded', timeout: maxWaitMs });
    await page.waitForLoadState('networkidle', { timeout: Math.min(maxWaitMs, 10_000) }).catch(() => {});
  } finally {
    page.off('request', requestListener);
    domExplorer.stopMonitoring(page);
  }

  await domExplorer.detectSPAFramework(page);

  const surfaces = await domExplorer.explore(page, capturedRequests);
  logger.info(`Discovered ${surfaces.length} surfaces on ${pageUrl}`);

  await page.close();
  await context.close();
  await browser.close();

  return surfaces;
}

async function main(): Promise<void> {
  const logger = makeLogger();

  const baseUrl = process.env['JUICESHOP_URL'] || DEFAULT_JUICESHOP_URL;
  const maxRoutes = Number(process.env['JUICESHOP_MAX_ROUTES'] || '15');
  const maxWaitMs = Number(process.env['JUICESHOP_TIMEOUT_MS'] || '30000');

  const domExplorer = new DomExplorer(LogLevel.INFO);

  logger.info(`Starting Juice Shop surface inventory for ${baseUrl}`);

  // 1) Explore base URL
  const surfacesByKey = new Map<string, AttackSurface>();

  const baseSurfaces = await exploreSingleUrl({ pageUrl: baseUrl, domExplorer, logger, maxWaitMs });
  for (const s of baseSurfaces) surfacesByKey.set(stableSurfaceKey(s), s);

  // 2) Collect hash routes (best-effort) and explore them to improve coverage
  try {
    const browser = await chromium.launch({ headless: true });
    const context = await browser.newContext();
    const page = await context.newPage();

    await page.goto(baseUrl, { waitUntil: 'domcontentloaded', timeout: maxWaitMs });
    await page.waitForLoadState('networkidle', { timeout: Math.min(maxWaitMs, 10_000) }).catch(() => {});

    await domExplorer.detectSPAFramework(page);
    const hashRoutes = await domExplorer.extractHashRoutes(page);

    await page.close();
    await context.close();
    await browser.close();

    const baseNoHash = baseUrl.split('#')[0];
    const uniqueRoutes = Array.from(new Set(hashRoutes)).slice(0, Math.max(0, maxRoutes));

    for (const route of uniqueRoutes) {
      const pageUrl = baseNoHash + route;
      const routeSurfaces = await exploreSingleUrl({ pageUrl, domExplorer, logger, maxWaitMs });
      for (const s of routeSurfaces) surfacesByKey.set(stableSurfaceKey(s), s);
    }
  } catch (e) {
    logger.warn(`Hash-route enrichment skipped/failed: ${e}`);
  }

  const surfaces = Array.from(surfacesByKey.values()).map(toSerializable);

  const summary = {
    baseUrl,
    executedAt: new Date().toISOString(),
    totals: {
      surfaces: surfaces.length,
      byType: surfaces.reduce<Record<string, number>>((acc, s) => {
        acc[s.type] = (acc[s.type] || 0) + 1;
        return acc;
      }, {}),
    },
    surfaces,
  };

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  await fs.writeFile(OUTPUT_PATH, JSON.stringify(summary, null, 2), 'utf-8');

  logger.info(`Wrote surface inventory to ${OUTPUT_PATH}`);
  logger.info(`Types: ${Object.entries(summary.totals.byType)
    .map(([t, n]) => `${t}=${n}`)
    .join(', ')}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exitCode = 1;
});
