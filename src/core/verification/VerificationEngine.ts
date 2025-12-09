/**
 * VerificationEngine - v0.2
 * Active verification system to reduce false positives/negatives
 */

import { Page } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Vulnerability } from '../../types/vulnerability';
import {
  VerificationLevel,
  VerificationStatus,
  VerificationConfig,
  VerificationResult,
  VerificationAttempt,
  VerificationStatistics,
  DEFAULT_VERIFICATION_CONFIGS,
  IVulnerabilityVerifier,
  TechniqueMetadata,
} from '../../types/verification';
import { TimeoutManager, getGlobalTimeoutManager } from '../timeout/TimeoutManager';
import { OperationType } from '../../types/timeout';

/**
 * VerificationEngine - Orchestrates vulnerability verification
 */
export class VerificationEngine {
  private logger: Logger;
  private verifiers: Map<string, IVulnerabilityVerifier> = new Map();
  private timeoutManager: TimeoutManager;
  private statistics: VerificationStatistics;

  constructor(
    timeoutManager?: TimeoutManager,
    logLevel: LogLevel = LogLevel.INFO
  ) {
    this.logger = new Logger(logLevel, 'VerificationEngine');
    this.timeoutManager = timeoutManager || getGlobalTimeoutManager();
    this.statistics = this.initializeStatistics();
  }

  /**
   * Initialize statistics
   */
  private initializeStatistics(): VerificationStatistics {
    return {
      totalProcessed: 0,
      confirmed: 0,
      falsePositives: 0,
      inconclusive: 0,
      averageConfidence: 0,
      averageTime: 0,
      accuracy: 0,
      networkErrors: 0,
      timeouts: 0,
      retries: 0,
      averageAttemptsPerVuln: 0,
    };
  }

  /**
   * Register a verifier
   */
  public registerVerifier(verifier: IVulnerabilityVerifier): void {
    this.verifiers.set(verifier.id, verifier);
    this.logger.info(`Registered verifier: ${verifier.name}`);
  }

  /**
   * Get configuration for a vulnerability type
   */
  private getConfig(vulnerabilityType: string): VerificationConfig {
    // Map vulnerability categories to config keys
    const typeMapping: Record<string, string> = {
      'SQL Injection': 'sql-injection',
      'SQL_INJECTION': 'sql-injection',
      'Cross-Site Scripting': 'xss',
      'XSS': 'xss',
      'Command Injection': 'command-injection',
      'COMMAND_INJECTION': 'command-injection',
      'Path Traversal': 'path-traversal',
      'PATH_TRAVERSAL': 'path-traversal',
      'SSRF': 'ssrf',
    };

    const configKey = typeMapping[vulnerabilityType] || 'default';
    const foundConfig = DEFAULT_VERIFICATION_CONFIGS[configKey] ?? DEFAULT_VERIFICATION_CONFIGS['default'];
    return foundConfig ?? {
      level: VerificationLevel.BASIC,
      minConfidence: 0.6,
      maxAttempts: 2,
      attemptTimeout: 10000,
      stopOnConfirm: true,
      enableMultiAttempt: true,
      maxPayloadVariations: 2,
    };
  }

  /**
   * Verify a single vulnerability
   */
  public async verify(
    vulnerability: Vulnerability,
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<VerificationResult> {
    const startTime = Date.now();
    const config = { ...this.getConfig(vulnerability.title), ...customConfig };
    if (config.enableMultiAttempt === undefined) config.enableMultiAttempt = config.level !== VerificationLevel.BASIC;
    if (config.maxPayloadVariations === undefined) config.maxPayloadVariations = 3;
    
    this.logger.info(`Verifying vulnerability: ${vulnerability.title} (Level: ${config.level})`);

    // Skip verification if level is NONE
    if (config.level === VerificationLevel.NONE) {
      return this.createResult(vulnerability, VerificationStatus.UNVERIFIED, 0.5, [], 0,
        'Verification skipped (level: NONE)');
    }

    const attempts: VerificationAttempt[] = [];
    
    const applicableVerifiers = this.findApplicableVerifiers(vulnerability);
    if (applicableVerifiers.length === 0) {
      this.logger.warn(`No verifiers found for: ${vulnerability.title}`);
      return this.createResult(
        vulnerability,
        VerificationStatus.INCONCLUSIVE,
        vulnerability.confidence || 0.5,
        [],
        Date.now() - startTime,
        'No applicable verifiers found'
      );
    }

    const prioritizedVerifiers = this.getTechniquesForLevel(config, applicableVerifiers, vulnerability);
    const metadataMap = new Map<string, TechniqueMetadata>();
    prioritizedVerifiers.forEach((v) => metadataMap.set(v.id, this.getTechniqueMetadata(v)));

    for (const verifier of prioritizedVerifiers) {
      if (config.stopOnConfirm && attempts.some((a) => a.success && a.confidence >= Math.max(config.minConfidence, 0.9))) {
        this.logger.debug(`Early exit after high-confidence confirmation; skipping ${verifier.name}`);
        break;
      }

      try {
        const verifierAttempts = config.enableMultiAttempt && config.level !== VerificationLevel.BASIC
          ? await this.runMultiAttemptVerification(verifier, vulnerability, page, config)
          : [await this.runVerificationAttempt(verifier, vulnerability, page, config)];

        attempts.push(...verifierAttempts);
      } catch (error) {
        const category = this.classifyError(error);
        this.logger.warn(`Verification technique ${verifier.name} failed: ${error}`);
        attempts.push({
          technique: verifier.name,
          success: false,
          confidence: 0,
          duration: Date.now() - startTime,
          error: String(error),
          errorCategory: category,
          retryCount: 0,
          timestamp: new Date(),
        });
      }
    }

    const duration = Date.now() - startTime;
    const successfulAttempts = attempts.filter((a) => a.success);
    const aggregatedConfidence = this.aggregateConfidence(attempts, metadataMap);

    // Edge-case handling: redirect loops should not be treated as confirmed failures
    const redirectDetected = attempts.some((a) => this.isRedirectLoop(String(a.details || '').toLowerCase()) || this.isRedirectLoop(String(a.error || '').toLowerCase()));
    if (redirectDetected && successfulAttempts.length === 0) {
      const reason = 'Redirect loop detected during verification';
      this.updateStatistics(VerificationStatus.INCONCLUSIVE, aggregatedConfidence, duration, attempts);
      return this.createResult(vulnerability, VerificationStatus.INCONCLUSIVE, aggregatedConfidence, attempts, duration, reason, false);
    }

    // Determine status
    let status: VerificationStatus;
    let shouldReport = false;
    let reason: string;

    const networkOnly = attempts.length > 0 && attempts.every((a) => a.errorCategory === 'network' || a.errorCategory === 'timeout');
    if (networkOnly) {
      status = VerificationStatus.INCONCLUSIVE;
      reason = 'Network or timeout errors prevented verification';
    } else if (successfulAttempts.length >= Math.ceil(prioritizedVerifiers.length / 2)) {
      status = aggregatedConfidence >= config.minConfidence ? VerificationStatus.CONFIRMED : VerificationStatus.VERIFIED;
      shouldReport = true;
      reason = `${successfulAttempts.length}/${prioritizedVerifiers.length} verification techniques passed`;
    } else if (successfulAttempts.length > 0) {
      status = VerificationStatus.VERIFIED;
      shouldReport = aggregatedConfidence >= config.minConfidence;
      reason = `${successfulAttempts.length}/${prioritizedVerifiers.length} techniques passed, confidence: ${aggregatedConfidence.toFixed(2)}`;
    } else {
      status = VerificationStatus.FALSE_POSITIVE;
      reason = 'All verification techniques failed';
    }

    this.updateStatistics(status, aggregatedConfidence, duration, attempts);

    return this.createResult(vulnerability, status, aggregatedConfidence, attempts, duration, reason, shouldReport);
  }

  /**
   * Verify multiple vulnerabilities
   */
  public async verifyAll(
    vulnerabilities: Vulnerability[],
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<VerificationResult[]> {
    const results: VerificationResult[] = [];
    
    for (const vuln of vulnerabilities) {
      try {
        const result = await this.verify(vuln, page, customConfig);
        results.push(result);
      } catch (error) {
        this.logger.error(`Failed to verify vulnerability ${vuln.id}: ${error}`);
        results.push(this.createResult(
          vuln, 
          VerificationStatus.INCONCLUSIVE, 
          0, 
          [], 
          0,
          `Verification error: ${error}`
        ));
      }
    }

    return results;
  }

  /**
   * Filter vulnerabilities to only confirmed ones
   */
  public async filterConfirmed(
    vulnerabilities: Vulnerability[],
    page: Page,
    customConfig?: Partial<VerificationConfig>
  ): Promise<Vulnerability[]> {
    const results = await this.verifyAll(vulnerabilities, page, customConfig);
    
    return results
      .filter(r => r.shouldReport)
      .map(r => ({
        ...r.vulnerability,
        confidence: r.confidence,
        confirmed: r.status === VerificationStatus.CONFIRMED,
        metadata: {
          ...r.vulnerability.metadata,
          verificationStatus: r.status,
          verificationAttempts: r.attempts.length,
          verificationTechniques: r.attempts.map(a => a.technique),
        },
      }));
  }

  /**
   * Run a single verification attempt
   */
  private async runVerificationAttempt(
    verifier: IVulnerabilityVerifier,
    vulnerability: Vulnerability,
    _page: Page,
    config: VerificationConfig,
    payloadVariation?: string
  ): Promise<VerificationAttempt> {
    const startTime = Date.now();
    let retries = 0;
    let lastError: any = null;
    let errorCategory: string | undefined;
    const maxRetries = Math.max(0, (config.maxAttempts ?? 1) - 1);

    while (retries <= maxRetries) {
      let timedOut = false;
      let result: VerificationResult | null = null;
      try {
        const wrapped = await this.timeoutManager.executeWithTimeout(
          OperationType.VERIFICATION,
          async () => verifier.verify(vulnerability, { ...config, payloadVariation }),
          { customTimeout: config.attemptTimeout }
        );
        timedOut = wrapped.timedOut;
        result = wrapped.result ?? null;
      } catch (err) {
        lastError = err;
        errorCategory = this.classifyError(err);
      }

      if (timedOut) {
        errorCategory = 'timeout';
        lastError = 'Verification timed out';
      }

      if (result) {
        return {
          technique: verifier.id,
          success: result.status === VerificationStatus.CONFIRMED || result.status === VerificationStatus.VERIFIED,
          confidence: result.confidence,
          duration: Date.now() - startTime,
          details: result.reason,
          errorCategory,
          retryCount: retries,
          payloadVariation,
          timestamp: new Date(),
        };
      }

      if ((errorCategory === 'network' || errorCategory === 'rate-limit') && retries < maxRetries) {
        retries++;
        const backoff = errorCategory === 'rate-limit' ? Math.min(5000, (retries + 1) * 1500) : retries * 1000;
        await new Promise((r) => setTimeout(r, backoff));
        continue;
      }

      break;
    }

    return {
      technique: verifier.id,
      success: false,
      confidence: 0,
      duration: Date.now() - startTime,
      error: String(lastError || 'Verification failed'),
      errorCategory,
      retryCount: retries,
      payloadVariation,
      timestamp: new Date(),
    };
  }

  private async runMultiAttemptVerification(
    verifier: IVulnerabilityVerifier,
    vulnerability: Vulnerability,
    page: Page,
    config: VerificationConfig
  ): Promise<VerificationAttempt[]> {
    const variations = this.generatePayloadVariations(vulnerability, config.maxPayloadVariations || 3);
    const attempts: VerificationAttempt[] = [];
    const attemptBudget = Math.max(1, config.maxAttempts ?? 1);
    let attemptsUsed = 0;

    for (const variation of variations) {
      const attempt = await this.runVerificationAttempt(verifier, vulnerability, page, config, variation);
      attempts.push(attempt);
      attemptsUsed += (attempt.retryCount ?? 0) + 1;
      if (config.stopOnConfirm && attempt.success && attempt.confidence >= Math.max(config.minConfidence, 0.9)) {
        break;
      }
      if (attemptsUsed >= attemptBudget) {
        this.logger.debug(`Stopping additional payload variations for ${verifier.name} due to maxAttempts budget`);
        break;
      }
    }

    return attempts;
  }

  private generatePayloadVariations(vulnerability: Vulnerability, max: number): string[] {
    const title = vulnerability.title.toLowerCase();
    const variations: string[] = [];
    if (/sql/.test(title)) {
      variations.push('single-quote', 'double-quote', 'comment', 'time-delay');
    } else if (/xss/.test(title)) {
      variations.push('html-tag', 'attribute', 'javascript-url');
    } else if (/command/.test(title)) {
      variations.push('pipe', 'semicolon', 'background');
    } else {
      variations.push('default');
    }
    return variations.slice(0, Math.max(1, max));
  }

  private aggregateConfidence(
    attempts: VerificationAttempt[],
    metadata: Map<string, TechniqueMetadata>
  ): number {
    if (!attempts.length) return 0;
    let weighted = 0;
    let weightTotal = 0;
    const allSuccess = attempts.every((a) => a.success);
    const mixedResults = attempts.some((a) => a.success) && attempts.some((a) => !a.success);

    for (const attempt of attempts) {
      const meta = metadata.get(attempt.technique);
      const weight = meta?.reliability ?? 1;
      weighted += attempt.confidence * weight;
      weightTotal += weight;
    }

    let confidence = weightTotal ? weighted / weightTotal : 0;
    if (allSuccess) confidence = Math.min(1, confidence + 0.05);
    if (mixedResults) confidence = Math.max(0, confidence - 0.1);
    return confidence;
  }

  /**
   * Find verifiers applicable to a vulnerability
   */
  private findApplicableVerifiers(vulnerability: Vulnerability): IVulnerabilityVerifier[] {
    const applicable: IVulnerabilityVerifier[] = [];
    
    for (const verifier of this.verifiers.values()) {
      const titleLower = vulnerability.title.toLowerCase();
      const categoryLower = vulnerability.category?.toLowerCase() || '';
      
      if (verifier.supportedTypes.some(type => 
        titleLower.includes(type.toLowerCase()) || categoryLower.includes(type.toLowerCase())
      )) {
        applicable.push(verifier);
      }
    }
    
    return applicable;
  }

  /**
   * Get techniques to run based on verification level
   */
  private getTechniquesForLevel(
    config: VerificationConfig,
    verifiers: IVulnerabilityVerifier[],
    vulnerability: Vulnerability
  ): IVulnerabilityVerifier[] {
    let prioritized = this.selectTechniquesForVulnerability(verifiers, vulnerability);

    // Filter by explicit technique list if provided
    if (config.techniques && config.techniques.length) {
      const allowed = new Set(config.techniques.map((t) => t.toLowerCase()));
      prioritized = prioritized.filter((v) => allowed.has(v.id.toLowerCase()));
    }

    // Manual override if provided
    if (config.techniqueOrder && config.techniqueOrder.length) {
      prioritized.sort((a, b) => {
        const idxA = config.techniqueOrder!.findIndex((id) => id.toLowerCase() === a.id.toLowerCase());
        const idxB = config.techniqueOrder!.findIndex((id) => id.toLowerCase() === b.id.toLowerCase());
        return (idxA === -1 ? Number.MAX_SAFE_INTEGER : idxA) - (idxB === -1 ? Number.MAX_SAFE_INTEGER : idxB);
      });
    }

    switch (config.level) {
      case VerificationLevel.BASIC:
        return prioritized.slice(0, 1);
      case VerificationLevel.STANDARD:
        return prioritized.slice(0, 2);
      case VerificationLevel.FULL:
        return prioritized;
      default:
        return [];
    }
  }

  /**
   * Create verification result
   */
  private createResult(
    vulnerability: Vulnerability,
    status: VerificationStatus,
    confidence: number,
    attempts: VerificationAttempt[],
    duration: number,
    reason: string,
    shouldReport: boolean = status !== VerificationStatus.FALSE_POSITIVE
  ): VerificationResult {
    return {
      vulnerability,
      status,
      confidence,
      attempts,
      totalDuration: duration,
      shouldReport,
      reason,
    };
  }

  private selectTechniquesForVulnerability(
    verifiers: IVulnerabilityVerifier[],
    vulnerability: Vulnerability
  ): IVulnerabilityVerifier[] {
    const type = vulnerability.title.toLowerCase();
    const prioritized: IVulnerabilityVerifier[] = [...verifiers];

    prioritized.sort((a, b) => {
      const metaA = this.getTechniqueMetadata(a);
      const metaB = this.getTechniqueMetadata(b);
      if (metaA.cost !== metaB.cost) return metaA.cost - metaB.cost;
      if (metaA.reliability !== metaB.reliability) return metaB.reliability - metaA.reliability;
      return metaA.speed - metaB.speed;
    });

    // Context-aware nudges
    const prefer = (name: string): number => prioritized.findIndex((v) => v.name.toLowerCase().includes(name));
    if (/sql/.test(type)) {
      this.promote(prioritized, prefer('response diff'), prefer('time-based'));
    } else if (/xss/.test(type)) {
      this.promote(prioritized, prefer('response diff'));
    } else if (/command/.test(type)) {
      this.promote(prioritized, prefer('time-based'));
    }

    return prioritized;
  }

  private promote(list: IVulnerabilityVerifier[], ...indexes: number[]): void {
    const valid = indexes.filter((i) => i >= 0);
    for (const idx of valid) {
      const [item] = list.splice(idx, 1);
      if (item) list.unshift(item);
    }
  }

  private getTechniqueMetadata(verifier: IVulnerabilityVerifier): TechniqueMetadata {
    const name = verifier.name.toLowerCase();
    if (name.includes('time')) return { name: verifier.id, cost: 5, reliability: 0.9, speed: 15000 };
    if (name.includes('response')) return { name: verifier.id, cost: 2, reliability: 0.95, speed: 3000 };
    if (name.includes('replay')) return { name: verifier.id, cost: 1, reliability: 0.6, speed: 1000 };
    return { name: verifier.id, cost: 3, reliability: 0.8, speed: 5000 };
  }

  /**
   * Update statistics
   */
  private updateStatistics(
    status: VerificationStatus,
    confidence: number,
    duration: number,
    attempts: VerificationAttempt[]
  ): void {
    this.statistics.totalProcessed++;
    
    switch (status) {
      case VerificationStatus.CONFIRMED:
        this.statistics.confirmed++;
        break;
      case VerificationStatus.FALSE_POSITIVE:
        this.statistics.falsePositives++;
        break;
      case VerificationStatus.INCONCLUSIVE:
        this.statistics.inconclusive++;
        break;
    }
    
    // Update averages
    const n = this.statistics.totalProcessed;
    this.statistics.averageConfidence = 
      ((this.statistics.averageConfidence * (n - 1)) + confidence) / n;
    this.statistics.averageTime = 
      ((this.statistics.averageTime * (n - 1)) + duration) / n;
    this.statistics.accuracy = this.statistics.confirmed / n;
    this.statistics.averageAttemptsPerVuln =
      ((this.statistics.averageAttemptsPerVuln * (n - 1)) + attempts.length) / n;

    this.statistics.networkErrors += attempts.filter((a) => a.errorCategory === 'network').length;
    this.statistics.timeouts += attempts.filter((a) => a.errorCategory === 'timeout').length;
    this.statistics.retries += attempts.reduce((sum, a) => sum + (a.retryCount || 0), 0);
  }

  /**
   * Get statistics
   */
  public getStatistics(): VerificationStatistics {
    return { ...this.statistics };
  }

  /**
   * Reset statistics
   */
  public resetStatistics(): void {
    this.statistics = this.initializeStatistics();
  }

  /**
   * Get registered verifier names
   */
  public getVerifierNames(): string[] {
    return Array.from(this.verifiers.keys());
  }

  /**
   * Categorize common failure modes so retries/backoffs remain intentional.
   * Rate limits trigger controlled backoff, redirects become inconclusive, and network/timeouts stay separate.
   */
  private classifyError(error: unknown): string {
    const message = String(error || '').toLowerCase();
    if (this.isRateLimit(message)) return 'rate-limit';
    if (message.includes('timeout') || message.includes('timed out')) return 'timeout';
    if (this.isNetworkError(message)) return 'network';
    if (this.isRedirectLoop(message)) return 'redirect';
    if (message.includes('500') || message.includes('internal server')) return 'application';
    return 'unknown';
  }

  private isNetworkError(message: string): boolean {
    return /econnrefused|etimedout|target closed|page closed|networkerror/i.test(message);
  }

  private isRateLimit(message: string): boolean {
    return /429|too many requests|rate limit|retry-after/i.test(message);
  }

  private isRedirectLoop(message: string): boolean {
    return /too many redirects|redirect loop|max redirects|infinite redirect/i.test(message);
  }
}

/**
 * Singleton instance
 */
let globalVerificationEngine: VerificationEngine | null = null;

export function getGlobalVerificationEngine(): VerificationEngine {
  if (!globalVerificationEngine) {
    globalVerificationEngine = new VerificationEngine();
  }
  return globalVerificationEngine;
}

export function resetGlobalVerificationEngine(): void {
  if (globalVerificationEngine) {
    globalVerificationEngine.resetStatistics();
  }
  globalVerificationEngine = null;
}
