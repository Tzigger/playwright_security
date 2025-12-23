import { chromium } from '@playwright/test';
import fs from 'fs/promises';
import path from 'path';

import { SqlInjectionDetector } from '../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../src/detectors/active/XssDetector';
import { InjectionDetector } from '../src/detectors/active/InjectionDetector';
import { IActiveDetector } from '../src/core/interfaces/IActiveDetector';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import { AttackSurface, AttackSurfaceType, InjectionContext } from '../src/scanners/active/DomExplorer';

type Expectation = 'positive' | 'negative' | 'candidate';

type DetectorKey = 'sqli' | 'xss' | 'cmdi';

type SerializableAttackSurface = Omit<AttackSurface, 'element'> & { element?: undefined };

type MetricsCase = {
  id: string;
  detector: DetectorKey;
  expectation: Expectation;
  baseUrl?: string;
  pageUrl?: string;
  surface: SerializableAttackSurface;
};

type CaseResult = {
  id: string;
  detector: DetectorKey;
  expectation: Expectation;
  baseUrl: string;
  pageUrl?: string;
  surfaceType: AttackSurfaceType;
  surfaceName: string;
  vulnerabilitiesFound: number;
  maxConfidence: number;
  evidenceCompleteCount: number;
  payloadsObserved: string[];
  cwes: string[];
  findings?: Array<{
    title: string;
    cwe?: string;
    confidence?: number;
    url?: string;
    payload?: string;
    requestUrl?: string;
    requestMethod?: string;
    responseStatus?: number;
  }>;
};

type MetricsSummary = {
  executedAt: string;
  totals: {
    cases: number;
    candidates: number;
    positives: number;
    negatives: number;
    tp: number;
    fp: number;
    fn: number;
    tn: number;
  };
  perDetector: Record<DetectorKey, {
    cases: number;
    tp: number;
    fp: number;
    fn: number;
    tn: number;
    precision: number | null;
    recall: number | null;
    avgConfidenceTP: number | null;
  }>;
  results: CaseResult[];
};

const DEFAULT_JUICESHOP_URL = 'http://localhost:3000';
const DEFAULT_CASES_PATH = path.join(process.cwd(), 'config', 'metrics', 'juiceshop-cases.json');
const OUTPUT_PATH = path.join(process.cwd(), 'test-security-reports', 'juiceshop-metrics.json');

function makeLogger(): Logger {
  return new Logger(LogLevel.INFO, 'juiceshop-metrics');
}

function mean(values: number[]): number | null {
  if (values.length === 0) return null;
  return values.reduce((sum, v) => sum + v, 0) / values.length;
}

function safeDiv(n: number, d: number): number | null {
  if (d === 0) return null;
  return n / d;
}

function detectorInstance(detector: DetectorKey): IActiveDetector {
  if (detector === 'sqli') return new SqlInjectionDetector();
  if (detector === 'xss') return new XssDetector();
  return new InjectionDetector(LogLevel.INFO, { permissiveMode: true });
}

function normalizeSurface(surface: SerializableAttackSurface, fallbackId: string): AttackSurface {
  return {
    id: surface.id || fallbackId,
    type: surface.type as AttackSurfaceType,
    selector: surface.selector,
    name: surface.name,
    value: surface.value,
    context: surface.context as InjectionContext,
    metadata: surface.metadata || {},
  };
}

async function runCase(args: {
  metricsCase: MetricsCase;
  defaultBaseUrl: string;
  page: any;
  logger: Logger;
}): Promise<CaseResult> {
  const { metricsCase, defaultBaseUrl, page, logger } = args;

  const safeMode = process.env['JUICESHOP_SAFE_MODE'] !== '0';

  const baseUrl = metricsCase.baseUrl || defaultBaseUrl;
  const pageUrl = metricsCase.pageUrl;
  const targetUrl = pageUrl || baseUrl;

  await page.goto(targetUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
  await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => {});

  const surface = normalizeSurface(metricsCase.surface, `metrics-${metricsCase.id}`);

  const detector = detectorInstance(metricsCase.detector);
  await detector.validate().catch(() => {});

  const vulns = await detector.detect({ page, attackSurfaces: [surface], baseUrl, safeMode });

  logger.info(
    `[${metricsCase.detector}] ${metricsCase.id} (${metricsCase.expectation}): found=${vulns.length} on ${surface.type} ${surface.name}`
  );

  const confidences = vulns.map((v) => v.confidence ?? 0);
  const maxConfidence = confidences.length ? Math.max(...confidences) : 0;

  const evidenceCompleteCount = vulns.filter((v) => Boolean(v.evidence?.request) && Boolean(v.evidence?.response)).length;

  const payloadsObserved = Array.from(
    new Set(
      vulns
        .map((v) => v.evidence?.payload)
        .filter((p): p is string => typeof p === 'string' && p.length > 0)
    )
  );

  const cwes = Array.from(new Set(vulns.map((v) => v.cwe).filter((cwe): cwe is string => Boolean(cwe))));

  const findings = vulns.slice(0, 3).map((v) => ({
    title: v.title,
    cwe: v.cwe,
    confidence: v.confidence,
    url: v.url,
    payload: v.evidence?.payload,
    requestUrl: v.evidence?.request?.url,
    requestMethod: v.evidence?.request?.method ? String(v.evidence.request.method) : undefined,
    responseStatus: v.evidence?.response?.status,
  }));

  return {
    id: metricsCase.id,
    detector: metricsCase.detector,
    expectation: metricsCase.expectation,
    baseUrl,
    pageUrl,
    surfaceType: surface.type,
    surfaceName: surface.name,
    vulnerabilitiesFound: vulns.length,
    maxConfidence,
    evidenceCompleteCount,
    payloadsObserved,
    cwes,
    findings: findings.length ? findings : undefined,
  };
}

function computeSummary(results: CaseResult[]): MetricsSummary {
  const candidates = results.filter((r) => r.expectation === 'candidate');
  const positives = results.filter((r) => r.expectation === 'positive');
  const negatives = results.filter((r) => r.expectation === 'negative');

  const tp = positives.filter((r) => r.vulnerabilitiesFound > 0).length;
  const fn = positives.filter((r) => r.vulnerabilitiesFound === 0).length;
  const fp = negatives.filter((r) => r.vulnerabilitiesFound > 0).length;
  const tn = negatives.filter((r) => r.vulnerabilitiesFound === 0).length;

  const perDetector = {
    sqli: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0, precision: null as number | null, recall: null as number | null, avgConfidenceTP: null as number | null },
    xss: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0, precision: null as number | null, recall: null as number | null, avgConfidenceTP: null as number | null },
    cmdi: { cases: 0, tp: 0, fp: 0, fn: 0, tn: 0, precision: null as number | null, recall: null as number | null, avgConfidenceTP: null as number | null },
  };

  for (const detector of Object.keys(perDetector) as DetectorKey[]) {
    const dr = results.filter((r) => r.detector === detector);
    perDetector[detector].cases = dr.length;

    const dp = dr.filter((r) => r.expectation === 'positive');
    const dn = dr.filter((r) => r.expectation === 'negative');

    perDetector[detector].tp = dp.filter((r) => r.vulnerabilitiesFound > 0).length;
    perDetector[detector].fn = dp.filter((r) => r.vulnerabilitiesFound === 0).length;
    perDetector[detector].fp = dn.filter((r) => r.vulnerabilitiesFound > 0).length;
    perDetector[detector].tn = dn.filter((r) => r.vulnerabilitiesFound === 0).length;

    perDetector[detector].precision = safeDiv(perDetector[detector].tp, perDetector[detector].tp + perDetector[detector].fp);
    perDetector[detector].recall = safeDiv(perDetector[detector].tp, perDetector[detector].tp + perDetector[detector].fn);

    const tpConfs = dr
      .filter((r) => r.expectation === 'positive' && r.vulnerabilitiesFound > 0)
      .map((r) => r.maxConfidence);
    perDetector[detector].avgConfidenceTP = mean(tpConfs);
  }

  return {
    executedAt: new Date().toISOString(),
    totals: {
      cases: results.length,
      candidates: candidates.length,
      positives: positives.length,
      negatives: negatives.length,
      tp,
      fp,
      fn,
      tn,
    },
    perDetector,
    results,
  };
}

async function main(): Promise<void> {
  const logger = makeLogger();

  const casesPath = process.env['JUICESHOP_CASES_PATH'] || DEFAULT_CASES_PATH;
  const defaultBaseUrl = process.env['JUICESHOP_URL'] || DEFAULT_JUICESHOP_URL;

  const raw = await fs.readFile(casesPath, 'utf-8');
  const cases = JSON.parse(raw) as MetricsCase[];

  if (!Array.isArray(cases) || cases.length === 0) {
    throw new Error(`No cases found in ${casesPath}. Add at least one case.`);
  }

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();

  const results: CaseResult[] = [];
  for (const c of cases) {
    const page = await context.newPage();
    try {
      results.push(await runCase({ metricsCase: c, defaultBaseUrl, page, logger }));
    } finally {
      await page.close().catch(() => {});
    }
  }
  await context.close();
  await browser.close();

  const summary = computeSummary(results);

  await fs.mkdir(path.dirname(OUTPUT_PATH), { recursive: true });
  await fs.writeFile(OUTPUT_PATH, JSON.stringify(summary, null, 2), 'utf-8');

  logger.info(`Wrote metrics to ${OUTPUT_PATH}`);
  logger.info(`Totals: TP=${summary.totals.tp}, FP=${summary.totals.fp}, FN=${summary.totals.fn}, TN=${summary.totals.tn}`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exitCode = 1;
});
