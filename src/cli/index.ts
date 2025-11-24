#!/usr/bin/env node
import { Command } from 'commander';
import { ScanEngine } from '../core/engine/ScanEngine';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { SqlInjectionDetector } from '../detectors/active/SqlInjectionDetector';
import { XssDetector } from '../detectors/active/XssDetector';
import { ErrorBasedDetector } from '../detectors/active/ErrorBasedDetector';
import { ScanConfiguration } from '../types/config';
import { AggressivenessLevel, AuthType, BrowserType, LogLevel, ReportFormat, VerbosityLevel } from '../types/enums';

const program = new Command();

program
  .name('dast-scan')
  .description('Run a DAST scan with Playwright Security')
  .argument('<url>', 'Target URL to scan')
  .option('-o, --output <dir>', 'Output directory for reports', 'reports')
  .option('-f, --formats <list>', 'Comma-separated report formats (console,json,html,sarif)', 'console,json,html')
  .option('--headless', 'Run headless browser', true)
  .option('--parallel <n>', 'Parallel scanners', '2')
  .action(async (url: string, options: any) => {
    const formats = String(options.formats)
      .split(',')
      .map((s: string) => s.trim().toLowerCase())
      .map((s: string) => s as unknown as ReportFormat);

    const config: ScanConfiguration = {
      target: {
        url,
        authentication: { type: AuthType.NONE },
        crawlDepth: 1,
        maxPages: 5,
        timeout: 30000,
      },
      scanners: {
        passive: { enabled: false },
        active: {
          enabled: true,
          aggressiveness: AggressivenessLevel.MEDIUM,
          submitForms: true,
        },
      },
      detectors: {
        enabled: [],
        sensitivity: 'normal' as any,
      },
      browser: {
        type: BrowserType.CHROMIUM,
        headless: options.headless !== false,
        timeout: 30000,
        viewport: { width: 1280, height: 800 },
      },
      reporting: {
        formats: formats as ReportFormat[],
        outputDir: options.output,
        verbosity: VerbosityLevel.NORMAL,
        // Don't set fileNameTemplate - let each reporter use its own default with extension
      },
      advanced: {
        parallelism: parseInt(options.parallel, 10) || 2,
        logLevel: LogLevel.INFO,
      },
    };

    const engine = new ScanEngine();

    // Prepare ActiveScanner with default detectors
    const active = new ActiveScanner();
    active.registerDetectors([
      new SqlInjectionDetector(),
      new XssDetector(),
      new ErrorBasedDetector(),
    ]);

    engine.registerScanner(active);
    await engine.loadConfiguration(config);
    await engine.scan();
    await engine.cleanup();
  });

program.parseAsync(process.argv).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
