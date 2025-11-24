import { ScanConfiguration } from '../../types/config';
import { ReportFormat, VerbosityLevel } from '../../types/enums';
import { Vulnerability } from '../../types/vulnerability';
import { ScanResult } from '../../types/scan-result';

export interface ReporterInitOptions {
  outputDir: string;
  verbosity: VerbosityLevel;
  includeScreenshots?: boolean;
  fileNameTemplate?: string;
  openInBrowser?: boolean;
}

export interface IReporter {
  getFormat(): ReportFormat;
  init(config: ScanConfiguration, options: ReporterInitOptions): Promise<void>;
  onScanStarted(scanId: string, config: ScanConfiguration): Promise<void>;
  onScannerStarted(scannerType: string): Promise<void>;
  onVulnerability(vuln: Vulnerability): Promise<void>;
  onScannerCompleted(scannerType: string): Promise<void>;
  onScanCompleted(result: ScanResult): Promise<void>;
  generate(result: ScanResult): Promise<void>;
}

export abstract class BaseReporter implements IReporter {
  protected config!: ScanConfiguration;
  protected options!: ReporterInitOptions;

  abstract getFormat(): ReportFormat;

  async init(config: ScanConfiguration, options: ReporterInitOptions): Promise<void> {
    this.config = config;
    this.options = options;
  }

  async onScanStarted(_scanId: string, _config: ScanConfiguration): Promise<void> {}
  async onScannerStarted(_scannerType: string): Promise<void> {}
  async onVulnerability(_vuln: Vulnerability): Promise<void> {}
  async onScannerCompleted(_scannerType: string): Promise<void> {}
  async onScanCompleted(_result: ScanResult): Promise<void> {}
  async generate(_result: ScanResult): Promise<void> {}
}
