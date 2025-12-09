#!/usr/bin/env node
import { Command } from 'commander';

import { ConfigurationManager } from '../core/config/ConfigurationManager';
import { ScanEngine } from '../core/engine/ScanEngine';
import { ErrorBasedDetector } from '../detectors/active/ErrorBasedDetector';
import { SqlInjectionDetector } from '../detectors/active/SqlInjectionDetector';
import { XssDetector } from '../detectors/active/XssDetector';
import { CookieSecurityDetector } from '../detectors/passive/CookieSecurityDetector';
import { HeaderSecurityDetector } from '../detectors/passive/HeaderSecurityDetector';
import { InsecureTransmissionDetector } from '../detectors/passive/InsecureTransmissionDetector';
import { SensitiveDataDetector } from '../detectors/passive/SensitiveDataDetector';
import { ActiveScanner } from '../scanners/active/ActiveScanner';
import { PassiveScanner } from '../scanners/passive/PassiveScanner';
import { ScanConfiguration } from '../types/config';
import { AggressivenessLevel, AuthType, BrowserType, LogLevel, ReportFormat, VerbosityLevel } from '../types/enums';

interface CliOptions {
  config?: string;
  output?: string;
  formats?: string;
  headless?: boolean;
  parallel?: string;
  passive?: boolean;
  active?: boolean;
  scanType?: string;
}

const program = new Command();

program
  .name('kinetic')
  .version('0.2.0')
  .description('Kinetic - High-performance DAST security scanner powered by Playwright')
  .argument('[url]', 'Target URL to scan (optional if using --config)')
  .option('-c, --config <file>', 'Load configuration from file')
  .option('-o, --output <dir>', 'Output directory for reports', 'reports')
  .option('-f, --formats <list>', 'Comma-separated report formats (console,json,html,sarif)', 'console,json,html')
  .option('--headless', 'Run headless browser', true)
  .option('--parallel <n>', 'Parallel scanners', '2')
  .option('--passive', 'Enable passive scanning (network interception, headers, cookies)')
  .option('--active', 'Enable active scanning (payload injection, fuzzing)', true)
  .option('--scan-type <type>', 'Scan type: active, passive, or both', 'active')
  .action(async (url: string | undefined, options: CliOptions) => {
    const configManager = ConfigurationManager.getInstance();
    let config: ScanConfiguration;

    // Load from config file if provided
    if (options.config) {
      try {
        config = await configManager.loadFromFile(options.config);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error(`Error loading configuration: ${String(error)}`);
        process.exit(1);
      }
      
      // CLI args override config file
      const overrides: Partial<ScanConfiguration> = {};
      if (url) {
        overrides.target = { ...config.target, url };
      }
      if (options.output) {
        overrides.reporting = { ...config.reporting, outputDir: options.output };
      }
      if (options.formats) {
        const formats = options.formats
          .split(',')
          .map((s: string) => s.trim().toLowerCase()) as ReportFormat[];
        overrides.reporting = { ...config.reporting, ...overrides.reporting, formats };
      }
      if (options.parallel) {
        overrides.advanced = { ...config.advanced, parallelism: parseInt(options.parallel, 10) || 2 };
      }

      config = configManager.mergeConfig(overrides);
    } else {
      // ... build config manually as before, but ideally use ConfigurationManager for defaults/validation too
      // For now, keep existing logic but ensure it's loaded into manager
      if (!url) {
        // eslint-disable-next-line no-console
        console.error('Error: URL required when not using --config');
        process.exit(1);
      }

      const formats = (options.formats || 'console,json,html')
        .split(',')
        .map((s: string) => s.trim().toLowerCase())
        .map((s: string) => s as unknown as ReportFormat);

      // Determine which scanners to enable based on flags
      const scanType = options.scanType?.toLowerCase() || 'active';
      const enablePassive = options.passive || scanType === 'passive' || scanType === 'both';
      const enableActive = options.active !== false && (scanType === 'active' || scanType === 'both');

      config = {
        target: {
          url,
          authentication: { type: AuthType.NONE },
          crawlDepth: 1,
          maxPages: 5,
          timeout: 30000,
        },
        scanners: {
          passive: { enabled: !!enablePassive },
          active: {
            enabled: !!enableActive,
            aggressiveness: AggressivenessLevel.MEDIUM,
            submitForms: true,
          },
        },
        detectors: {
          enabled: [],
          // eslint-disable-next-line @typescript-eslint/no-explicit-any, @typescript-eslint/no-unsafe-assignment
          sensitivity: 'normal' as any,
        },
        browser: {
          type: BrowserType.CHROMIUM,
          headless: options.headless !== false,
          timeout: 30000,
          viewport: { width: 1280, height: 800 },
        },
        reporting: {
          formats: formats,
          outputDir: options.output || 'reports',
          verbosity: VerbosityLevel.NORMAL,
        },
        advanced: {
          parallelism: parseInt(options.parallel || '2', 10) || 2,
          logLevel: LogLevel.INFO,
        },
      };
      // Validate and load manual config
      configManager.loadFromObject(config);
    }

    const engine = new ScanEngine();

    // Register scanners based on configuration
    if (config.scanners.active?.enabled) {
      const active = new ActiveScanner();
      active.registerDetectors([
        new SqlInjectionDetector(),
        new XssDetector(),
        new ErrorBasedDetector(),
      ]);
      engine.registerScanner(active);
    }

    if (config.scanners.passive?.enabled) {
      const passive = new PassiveScanner();
      passive.registerDetectors([
        new SensitiveDataDetector(),
        new HeaderSecurityDetector(),
        new CookieSecurityDetector(),
        new InsecureTransmissionDetector(),
      ]);
      engine.registerScanner(passive);
    }

    await engine.loadConfiguration(config);
    await engine.scan();
    await engine.cleanup();
  });

program.parseAsync(process.argv).catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
