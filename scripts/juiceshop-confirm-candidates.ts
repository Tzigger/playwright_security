import { chromium } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';

type DetectorKey = 'sqli' | 'xss' | 'cmdi';

type MetricsResult = {
  id: string;
  detector: DetectorKey;
  expectation: 'positive' | 'negative' | 'candidate';
  baseUrl: string;
  pageUrl?: string;
  payloadsObserved?: string[];
  findings?: Array<{ payload?: string; url?: string; requestUrl?: string; requestMethod?: string; responseStatus?: number }>;
};

type MetricsFile = {
  executedAt: string;
  results: MetricsResult[];
};

type ConfirmationStatus = 'confirmed' | 'rejected' | 'inconclusive';

type ConfirmationResult = {
  id: string;
  detector: DetectorKey;
  baseUrl: string;
  pageUrl?: string;
  payload?: string;
  status: ConfirmationStatus;
  reason: string;
  details?: Record<string, unknown>;
};

type ConfirmationsFile = {
  executedAt: string;
  sourceMetricsPath: string;
  results: ConfirmationResult[];
};

const DEFAULT_JUICESHOP_URL = 'http://localhost:3000';
const DEFAULT_METRICS_PATH = path.join(process.cwd(), 'test-security-reports', 'juiceshop-metrics.json');
const OUTPUT_PATH = path.join(process.cwd(), 'test-security-reports', 'juiceshop-confirmations.json');

function makeLogger(): Logger {
  return new Logger(LogLevel.INFO, 'juiceshop-confirm');
}

function firstPayload(result: MetricsResult): string | undefined {
  const p1 = result.payloadsObserved?.find((p) => typeof p === 'string' && p.length > 0);
  if (p1) return p1;
  const p2 = result.findings?.map((f) => f.payload).find((p) => typeof p === 'string' && p.length > 0);
  return p2;
}

function tryParseJson(text: string): any | null {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

async function confirmXss(args: {
  baseUrl: string;
  pageUrl?: string;
  payload: string;
  logger: Logger;
}): Promise<Omit<ConfirmationResult, 'id' | 'detector'>> {
  const { baseUrl, pageUrl, payload, logger } = args;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  await page.addInitScript(() => {
    // Avoid blocking dialogs; capture execution as proof.
    (window as any).__kineticAlertCalled = false;
    (window as any).__kineticAlertMessage = undefined;

    const original = window.alert;
    window.alert = (msg?: any) => {
      (window as any).__kineticAlertCalled = true;
      (window as any).__kineticAlertMessage = String(msg);
      try {
        // Keep behavior non-blocking.
        return undefined;
      } finally {
        // no-op
      }
    };

    // Preserve original reference for debugging if needed.
    (window as any).__kineticOriginalAlert = original;
  });

  const errors: string[] = [];
  page.on('pageerror', (err) => errors.push(String(err)));

  const consoleMessages: string[] = [];
  page.on('console', (msg) => {
    const text = msg.text();
    if (typeof text === 'string' && text.length) consoleMessages.push(text);
  });

  const candidateUrls: string[] = [];
  // Try the exact URL form the detector reported.
  if (payload.startsWith('http://') || payload.startsWith('https://')) {
    candidateUrls.push(payload);
  } else if (payload.startsWith('#')) {
    candidateUrls.push(`${baseUrl}${payload}`);
    // Also try applying the hash onto an actual SPA route.
    if (pageUrl) candidateUrls.push(`${pageUrl}${payload}`);
    candidateUrls.push(`${baseUrl}/#/${payload}`);
  } else {
    candidateUrls.push(`${baseUrl}${payload}`);
  }

  let navigatedUrl: string | undefined;
  let alertCalled = false;
  let alertMessage: string | undefined;

  for (const url of candidateUrls) {
    try {
      await page.goto(pageUrl || `${baseUrl}/#/`, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});

      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: 30000 });
      await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});

      navigatedUrl = url;
      alertCalled = await page.evaluate(() => Boolean((window as any).__kineticAlertCalled));
      alertMessage = await page.evaluate(() => (window as any).__kineticAlertMessage as string | undefined);

      if (alertCalled) {
        break;
      }
    } catch (e) {
      errors.push(`navigate(${url}): ${String(e)}`);
    }
  }

  await page.close().catch(() => {});
  await context.close().catch(() => {});
  await browser.close().catch(() => {});

  if (!navigatedUrl) {
    return {
      baseUrl,
      pageUrl,
      payload,
      status: 'inconclusive',
      reason: 'Navigation failed for all attempted URLs',
      details: { attemptedUrls: candidateUrls, errors, consoleMessages: consoleMessages.slice(0, 20) },
    };
  }

  if (alertCalled) {
    logger.info(`XSS confirmed via alert() on ${navigatedUrl}`);
    return {
      baseUrl,
      pageUrl,
      payload,
      status: 'confirmed',
      reason: 'Observed JavaScript execution (alert() was called)',
      details: { navigatedUrl, alertMessage, errors: errors.slice(0, 10), consoleMessages: consoleMessages.slice(0, 20) },
    };
  }

  return {
    baseUrl,
    pageUrl,
    payload,
    status: 'rejected',
    reason: 'No JavaScript execution observed for the provided payload',
    details: { attemptedUrls: candidateUrls, navigatedUrl, errors: errors.slice(0, 10), consoleMessages: consoleMessages.slice(0, 20) },
  };
}

function extractProductCount(json: any): number | null {
  if (!json || typeof json !== 'object') return null;
  const data = (json as any).data;
  if (Array.isArray(data)) return data.length;
  // Some variants may return a plain array.
  if (Array.isArray(json)) return json.length;
  return null;
}

async function confirmSqli(args: {
  baseUrl: string;
  payload: string;
  logger: Logger;
}): Promise<Omit<ConfirmationResult, 'id' | 'detector'>> {
  const { baseUrl, payload, logger } = args;

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();

  const request = context.request;

  const endpoint = `${baseUrl.replace(/\/$/, '')}/rest/products/search`;

  const baselineQ = 'apple';
  const controlFalse = "' AND 'a'='b";

  const probes = [
    { name: 'baseline', q: baselineQ },
    { name: 'candidate', q: payload },
    { name: 'falseControl', q: controlFalse },
  ];

  const observations: Array<{
    name: string;
    url: string;
    status?: number;
    ok?: boolean;
    productCount?: number | null;
    parseOk: boolean;
    textSample?: string;
  }> = [];

  for (const p of probes) {
    const url = `${endpoint}?q=${encodeURIComponent(p.q)}`;
    try {
      const resp = await request.get(url, { timeout: 15000 });
      const status = resp.status();
      const text = await resp.text();
      const json = tryParseJson(text);
      const productCount = extractProductCount(json);

      observations.push({
        name: p.name,
        url,
        status,
        ok: resp.ok(),
        productCount,
        parseOk: json !== null,
        textSample: json === null ? text.slice(0, 300) : undefined,
      });
    } catch (e) {
      observations.push({ name: p.name, url, parseOk: false, textSample: `request_error: ${String(e)}` });
    }
  }

  await context.close().catch(() => {});
  await browser.close().catch(() => {});

  const baseline = observations.find((o) => o.name === 'baseline');
  const candidate = observations.find((o) => o.name === 'candidate');
  const falseCtl = observations.find((o) => o.name === 'falseControl');

  const parseAllOk = Boolean(baseline?.parseOk && candidate?.parseOk && falseCtl?.parseOk);

  if (!parseAllOk) {
    return {
      baseUrl,
      payload,
      status: 'inconclusive',
      reason: 'Could not reliably parse one or more probe responses as JSON',
      details: { endpoint, observations },
    };
  }

  const candidateCount = candidate?.productCount;
  const falseCount = falseCtl?.productCount;

  if (typeof candidateCount === 'number' && typeof falseCount === 'number') {
    const delta = candidateCount - falseCount;
    // Conservative confirmation rule: clear boolean-style differential.
    const confirmed = candidateCount >= 5 && delta >= 3;

    if (confirmed) {
      logger.info(`SQLi likely confirmed: candidateCount=${candidateCount}, falseCount=${falseCount}`);
      return {
        baseUrl,
        payload,
        status: 'confirmed',
        reason: 'Observed a strong response differential between candidate and false control probes',
        details: { endpoint, candidateCount, falseCount, delta, observations },
      };
    }

    return {
      baseUrl,
      payload,
      status: 'rejected',
      reason: 'No strong boolean-style response differential observed for the provided payload',
      details: { endpoint, candidateCount, falseCount, delta, observations },
    };
  }

  return {
    baseUrl,
    payload,
    status: 'inconclusive',
    reason: 'Probe responses did not contain a recognizable product list for comparison',
    details: { endpoint, observations },
  };
}

async function main(): Promise<void> {
  const logger = makeLogger();

  const metricsPath = process.env['JUICESHOP_METRICS_PATH'] || DEFAULT_METRICS_PATH;
  const defaultBaseUrl = process.env['JUICESHOP_URL'] || DEFAULT_JUICESHOP_URL;

  const raw = await fs.readFile(metricsPath, 'utf-8');
  const metrics = JSON.parse(raw) as MetricsFile;

  if (!metrics || !Array.isArray(metrics.results)) {
    throw new Error(`Invalid metrics file at ${metricsPath}`);
  }

  const candidates = metrics.results.filter((r) => r.expectation === 'candidate');
  if (candidates.length === 0) {
    throw new Error(`No candidate cases found in metrics (${metricsPath}). Run juice:metrics first.`);
  }

  const results: ConfirmationResult[] = [];

  for (const c of candidates) {
    const baseUrl = c.baseUrl || defaultBaseUrl;
    const payload = firstPayload(c);

    if (!payload) {
      results.push({
        id: c.id,
        detector: c.detector,
        baseUrl,
        pageUrl: c.pageUrl,
        status: 'inconclusive',
        reason: 'No payload observed in metrics output for this case',
      });
      continue;
    }

    logger.info(`Confirming ${c.id} (${c.detector}) with payload: ${payload}`);

    if (c.detector === 'xss') {
      const r = await confirmXss({ baseUrl, pageUrl: c.pageUrl, payload, logger });
      results.push({ id: c.id, detector: c.detector, ...r });
      continue;
    }

    if (c.detector === 'sqli') {
      const r = await confirmSqli({ baseUrl, payload, logger });
      results.push({ id: c.id, detector: c.detector, pageUrl: c.pageUrl, ...r });
      continue;
    }

    results.push({
      id: c.id,
      detector: c.detector,
      baseUrl,
      pageUrl: c.pageUrl,
      payload,
      status: 'inconclusive',
      reason: 'No confirmation strategy implemented for this detector yet',
    });
  }

  const out: ConfirmationsFile = {
    executedAt: new Date().toISOString(),
    sourceMetricsPath: metricsPath,
    results,
  };

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  await fs.writeFile(OUTPUT_PATH, JSON.stringify(out, null, 2), 'utf-8');

  const counts = results.reduce(
    (acc, r) => {
      acc[r.status] = (acc[r.status] || 0) + 1;
      return acc;
    },
    {} as Record<ConfirmationStatus, number>
  );

  logger.info(`Wrote confirmations to ${OUTPUT_PATH}`);
  logger.info(`Summary: confirmed=${counts.confirmed || 0}, rejected=${counts.rejected || 0}, inconclusive=${counts.inconclusive || 0}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exitCode = 1;
});
