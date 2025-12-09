import { randomBytes } from 'crypto';
import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory, LogLevel } from '../../types/enums';
import { AttackSurface, InjectionContext, AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';
import { getOWASP2025Category } from '../../utils/cwe/owasp-2025-mapping';
import { Logger } from '../../utils/logger/Logger';
import {
  detectHtmlEncoding,
  detectUrlEncoding,
  detectJsEncoding,
  detectEncodingLevel,
  detectReflectionContext,
  analyzeReflectionQuality,
  findReflectionPatterns,
  calculateReflectionConfidence,
  EXECUTION_INDICATOR_PATTERNS,
  ReflectionContext,
  EncodingType,
} from '../../utils/patterns/xss-patterns';

interface TechniqueTimeouts {
  reflected: number;
  stored: number;
  domBased: number;
  angularTemplate: number;
  jsonXss: number;
}

interface XssDetectorConfig {
  techniqueTimeouts?: Partial<TechniqueTimeouts>;
  skipRedundantTests?: boolean;
  allowDuplicatePayloads?: boolean;
  minConfidenceForEarlyExit?: number;
  enableReflected?: boolean;
  enableStored?: boolean;
  enableDomBased?: boolean;
  enableAngularTemplate?: boolean;
  enableJsonXss?: boolean;
  maxSurfacesPerPage?: number;
  checkEncoding?: boolean;
  prioritizePayloads?: boolean;
}

type ResolvedXssDetectorConfig = Required<Omit<XssDetectorConfig, 'techniqueTimeouts'>> & {
  techniqueTimeouts: TechniqueTimeouts;
};

interface XssDetectorStats {
  surfacesTested: number;
  timeouts: number;
  vulnsFound: number;
  attempts: Record<XssType, number>;
  timeoutsByTechnique: Record<XssType, number>;
}

const DEFAULT_XSS_DETECTOR_CONFIG: ResolvedXssDetectorConfig = {
  techniqueTimeouts: {
    reflected: 10000,
    stored: 15000,
    domBased: 8000,
    angularTemplate: 12000,
    jsonXss: 10000,
  },
  skipRedundantTests: true,
  allowDuplicatePayloads: false,
  minConfidenceForEarlyExit: 0.9,
  enableReflected: true,
  enableStored: true,
  enableDomBased: true,
  enableAngularTemplate: true,
  enableJsonXss: true,
  maxSurfacesPerPage: 5,
  checkEncoding: true,
  prioritizePayloads: true,
};

/**
 * XSS Detection Types
 */
export enum XssType {
  REFLECTED = 'reflected',
  STORED = 'stored',
  DOM_BASED = 'dom-based',
  ANGULAR_TEMPLATE = 'angular-template',
  JSON_XSS = 'json-xss',
}

/**
 * XSS Detector - Detects Cross-Site Scripting vulnerabilities
 * Implements context-aware payload injection for HTML, JavaScript, URL, and template contexts
 */
export class XssDetector implements IActiveDetector {
  readonly name = 'XSS Detector';
  readonly description = 'Detects Cross-Site Scripting (XSS) vulnerabilities with context-aware payloads';
  readonly version = '1.1.0';

  private injector: PayloadInjector;
  private logger: Logger;
  private stats: XssDetectorStats;
  private config: ResolvedXssDetectorConfig;
  private testedPayloads: Map<string, Set<string>> = new Map();

  constructor(config: XssDetectorConfig = {}) {
    this.injector = new PayloadInjector();
    this.logger = new Logger(LogLevel.INFO, 'XssDetector');
    this.config = this.mergeConfig(DEFAULT_XSS_DETECTOR_CONFIG, config);
    this.stats = this.initStats();
  }

  public updateConfig(config: Partial<XssDetectorConfig>): void {
    this.config = this.mergeConfig(this.config, config);
  }

  private mergeConfig(base: ResolvedXssDetectorConfig, overrides: Partial<XssDetectorConfig>): ResolvedXssDetectorConfig {
    return {
      ...base,
      ...overrides,
      techniqueTimeouts: { ...base.techniqueTimeouts, ...(overrides.techniqueTimeouts ?? {}) },
    };
  }

  public setTechniqueTimeout(technique: XssType, timeout: number): void {
    if (technique === XssType.REFLECTED) this.config.techniqueTimeouts.reflected = timeout;
    if (technique === XssType.STORED) this.config.techniqueTimeouts.stored = timeout;
    if (technique === XssType.DOM_BASED) this.config.techniqueTimeouts.domBased = timeout;
    if (technique === XssType.ANGULAR_TEMPLATE) this.config.techniqueTimeouts.angularTemplate = timeout;
    if (technique === XssType.JSON_XSS) this.config.techniqueTimeouts.jsonXss = timeout;
  }

  private initStats(): XssDetectorStats {
    return {
      surfacesTested: 0,
      timeouts: 0,
      vulnsFound: 0,
      attempts: {
        [XssType.REFLECTED]: 0,
        [XssType.STORED]: 0,
        [XssType.DOM_BASED]: 0,
        [XssType.ANGULAR_TEMPLATE]: 0,
        [XssType.JSON_XSS]: 0,
      },
      timeoutsByTechnique: {
        [XssType.REFLECTED]: 0,
        [XssType.STORED]: 0,
        [XssType.DOM_BASED]: 0,
        [XssType.ANGULAR_TEMPLATE]: 0,
        [XssType.JSON_XSS]: 0,
      },
    };
  }

  /**
   * Helper: Run a promise with timeout
   */
  private async withTimeout<T>(
    promise: Promise<T>,
    timeoutMs: number,
    label: string,
    statsKey?: XssType
  ): Promise<T | null> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<null>((resolve) => {
      timer = setTimeout(() => {
        this.logger.debug(`${label} timed out after ${timeoutMs}ms`);
        this.stats.timeouts += 1;
        if (statsKey) this.stats.timeoutsByTechnique[statsKey] += 1;
        resolve(null);
      }, timeoutMs);
    });

    const result = await Promise.race([promise, timeoutPromise]);
    if (timer) clearTimeout(timer);
    return result as T | null;
  }

  /**
   * Detect XSS vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    this.stats = this.initStats();
    this.testedPayloads.clear();

    const xssTargets = attackSurfaces.filter(
      (surface) =>
        surface.context === InjectionContext.HTML ||
        surface.context === InjectionContext.HTML_ATTRIBUTE ||
        surface.context === InjectionContext.JAVASCRIPT ||
        surface.context === InjectionContext.URL ||
        surface.context === InjectionContext.JSON ||
        surface.type === AttackSurfaceType.API_PARAM ||
        surface.type === AttackSurfaceType.JSON_BODY
    );

    const prioritizedTargets = this.prioritizeTargets(xssTargets).slice(0, this.config.maxSurfacesPerPage);

    for (const surface of prioritizedTargets) {
      this.stats.surfacesTested += 1;
      const surfaceFindings: Vulnerability[] = [];
      const techniqueOrder = this.getTechniqueOrder(surface);

      for (const technique of techniqueOrder) {
        if (this.shouldSkipTechnique(technique, surfaceFindings)) continue;
        if (!this.isTechniqueEnabled(technique)) continue;

        this.logTechniqueStart(technique, surface);
        const stepStart = Date.now();
        let vuln: Vulnerability | null = null;

        try {
          if (technique === XssType.REFLECTED) {
            this.stats.attempts[XssType.REFLECTED] += 1;
            vuln = await this.withTimeout(
              this.testReflectedXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.reflected,
              'testReflectedXss',
              XssType.REFLECTED
            );
          } else if (technique === XssType.STORED) {
            this.stats.attempts[XssType.STORED] += 1;
            vuln = await this.withTimeout(
              this.testStoredXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.stored,
              'testStoredXss',
              XssType.STORED
            );
          } else if (technique === XssType.DOM_BASED) {
            this.stats.attempts[XssType.DOM_BASED] += 1;
            vuln = await this.withTimeout(
              this.testDomBasedXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.domBased,
              'testDomBasedXss',
              XssType.DOM_BASED
            );
          } else if (technique === XssType.ANGULAR_TEMPLATE) {
            this.stats.attempts[XssType.ANGULAR_TEMPLATE] += 1;
            vuln = await this.withTimeout(
              this.testAngularTemplateInjection(page, surface, baseUrl),
              this.config.techniqueTimeouts.angularTemplate,
              'testAngularTemplateInjection',
              XssType.ANGULAR_TEMPLATE
            );
          } else if (technique === XssType.JSON_XSS) {
            this.stats.attempts[XssType.JSON_XSS] += 1;
            vuln = await this.withTimeout(
              this.testJsonXss(page, surface, baseUrl),
              this.config.techniqueTimeouts.jsonXss,
              'testJsonXss',
              XssType.JSON_XSS
            );
          }
        } catch (error) {
          this.logger.warn(`Error executing ${technique} on ${surface.name}: ${error}`);
        }

        this.logTechniqueResult(technique, Boolean(vuln), Date.now() - stepStart);

        if (vuln) {
          vulnerabilities.push(vuln);
          surfaceFindings.push(vuln);
          this.stats.vulnsFound += 1;
          const confidence = (vuln.evidence as any)?.metadata?.confidence || 0;
          if (this.config.skipRedundantTests && confidence >= this.config.minConfidenceForEarlyExit) {
            break;
          }
        }
      }
    }

    return vulnerabilities;
  }

  private prioritizeTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces
      .map((surface) => ({ surface, score: this.scoreSurface(surface) }))
      .sort((a, b) => b.score - a.score)
      .map((entry) => entry.surface);
  }

  private scoreSurface(surface: AttackSurface): number {
    let score = 0;
    const nameLower = surface.name.toLowerCase();
    const inputType = String(surface.metadata?.inputType || '').toLowerCase();

    if (['search', 'query', 'comment', 'message', 'name', 'title', 'description'].some((key) => nameLower.includes(key))) {
      score += 10;
    }

    if (['text', 'textarea', 'search'].includes(inputType)) score += 5;
    if (['checkbox', 'radio', 'submit', 'button', 'file', 'hidden'].includes(inputType)) score -= 5;

    if (surface.context === InjectionContext.HTML || surface.context === InjectionContext.JAVASCRIPT) score += 5;
    if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) score += 3;

    return score;
  }

  private getTechniqueOrder(surface: AttackSurface): XssType[] {
    const order: XssType[] = [];

    if (surface.type === AttackSurfaceType.API_PARAM || surface.type === AttackSurfaceType.JSON_BODY) {
      order.push(XssType.JSON_XSS, XssType.ANGULAR_TEMPLATE);
    }

    if (surface.type === AttackSurfaceType.URL_PARAMETER || surface.type === AttackSurfaceType.LINK) {
      order.push(XssType.REFLECTED, XssType.DOM_BASED);
    }

    if (surface.type === AttackSurfaceType.FORM_INPUT) {
      order.push(XssType.REFLECTED, XssType.ANGULAR_TEMPLATE, XssType.STORED);
    }

    const allTechniques = [
      XssType.REFLECTED,
      XssType.ANGULAR_TEMPLATE,
      XssType.JSON_XSS,
      XssType.DOM_BASED,
      XssType.STORED,
    ];

    for (const tech of allTechniques) {
      if (!order.includes(tech)) order.push(tech);
    }

    return order;
  }

  private shouldSkipTechnique(technique: XssType, findings: Vulnerability[]): boolean {
    if (!this.config.skipRedundantTests) return false;
    const highConfidenceFound = findings.some((vuln) => {
      const confidence = (vuln.evidence as any)?.metadata?.confidence || 0;
      return confidence >= this.config.minConfidenceForEarlyExit;
    });
    return highConfidenceFound;
  }

  private isTechniqueEnabled(technique: XssType): boolean {
    switch (technique) {
      case XssType.REFLECTED:
        return this.config.enableReflected;
      case XssType.STORED:
        return this.config.enableStored;
      case XssType.DOM_BASED:
        return this.config.enableDomBased;
      case XssType.ANGULAR_TEMPLATE:
        return this.config.enableAngularTemplate;
      case XssType.JSON_XSS:
        return this.config.enableJsonXss;
      default:
        return true;
    }
  }

  private getSurfaceKey(surface: AttackSurface): string {
    return `${surface.type}-${surface.name}-${surface.metadata?.url || ''}`;
  }

  private hasTestedPayload(surface: AttackSurface, payload: string): boolean {
    if (this.config.allowDuplicatePayloads) return false;
    const key = this.getSurfaceKey(surface);
    return this.testedPayloads.get(key)?.has(payload) || false;
  }

  private markPayloadTested(surface: AttackSurface, payload: string): void {
    const key = this.getSurfaceKey(surface);
    if (!this.testedPayloads.has(key)) {
      this.testedPayloads.set(key, new Set());
    }
    this.testedPayloads.get(key)!.add(payload);
  }

  private async analyzeReflectionContext(
    page: Page,
    surface: AttackSurface,
    baseUrl: string,
    testValue: string
  ): Promise<{ context: ReflectionContext; encoding: EncodingType; encodingLevel: 'none' | 'partial' | 'full'; html: string } | null> {
    try {
      const result = await this.injector.inject(page, surface, testValue, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      const html = result.response?.body || '';
      const context = detectReflectionContext(html, testValue);
      const htmlEncoding = detectHtmlEncoding(html, testValue);
      const urlEncoding = detectUrlEncoding(html, testValue);
      const jsEncoding = detectJsEncoding(html, testValue);
      const encoding: EncodingType = htmlEncoding !== 'none' ? 'html' : urlEncoding !== 'none' ? 'url' : jsEncoding !== 'none' ? 'js' : 'none';
      const encodingLevel = detectEncodingLevel(html, testValue);

      return { context, encoding, encodingLevel, html };
    } catch (error) {
      this.logger.debug(`Failed to analyze reflection context for ${surface.name}: ${error}`);
      return null;
    }
  }

  private getContextAwarePayloads(
    surface: AttackSurface,
    reflectionContext: ReflectionContext,
    encoding: EncodingType
  ): string[] {
    const basePayloads: string[] = [];

    const fastHtml = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
    ];

    const attributeBreakout = [
      '" autofocus onfocus=alert("XSS") "',
      "' onfocus=alert('XSS') '",
      '" onmouseover=alert("XSS") "',
    ];

    const jsContext = [
      '";alert("XSS");//',
      "';alert('XSS');//",
      '</script><script>alert("XSS")</script>',
    ];

    const urlContext = [
      'javascript:alert("XSS")',
      'data:text/html,<script>alert("XSS")</script>',
    ];

    if (reflectionContext === 'html-attribute') {
      basePayloads.push(...attributeBreakout, ...fastHtml);
    } else if (reflectionContext === 'javascript') {
      basePayloads.push(...jsContext, ...fastHtml);
    } else if (reflectionContext === 'url') {
      basePayloads.push(...urlContext, ...fastHtml);
    } else {
      basePayloads.push(...fastHtml, ...attributeBreakout, ...jsContext, ...urlContext);
    }

    const encodingBypasses: string[] = [];
    if (encoding === 'html') {
      encodingBypasses.push(
        '<scr\x69pt>alert(1)</scr\x69pt>',
        '<img src=x onerror=window["al"+"ert"](1)>',
        '&#x3c;img src=x onerror=alert(1)&#x3e;'
      );
    }
    if (encoding === 'url') {
      encodingBypasses.push(
        '%3Cscript%3Ealert(1)%3C/script%3E',
        '%253Cscript%253Ealert(1)%253C/script%253E'
      );
    }
    if (encoding === 'js') {
      encodingBypasses.push(
        '\\x3cscript\\x3ealert(1)\\x3c/script\\x3e',
        '\\u003cscript\\u003ealert(1)\\u003c/script\\u003e'
      );
    }

    const prioritized = this.config.prioritizePayloads ? basePayloads : [...new Set([...basePayloads, ...encodingBypasses])];
    return [...new Set([...prioritized, ...encodingBypasses])];
  }

  private analyzeReflection(result: InjectionResult, payload: string) {
    const body = result.response?.body || '';
    const patterns = findReflectionPatterns(body, payload);
    const context = detectReflectionContext(body, payload);
    const encodingType = this.config.checkEncoding
      ? (detectHtmlEncoding(body, payload) !== 'none'
          ? 'html'
          : detectUrlEncoding(body, payload) !== 'none'
            ? 'url'
            : detectJsEncoding(body, payload) !== 'none'
              ? 'js'
              : 'none')
      : 'none';
    const encodingLevel = this.config.checkEncoding ? detectEncodingLevel(body, payload) : 'none';
    const quality = analyzeReflectionQuality(body, payload);
    const executionIndicators = EXECUTION_INDICATOR_PATTERNS.filter((pattern) => pattern.test(body)).map((p) => p.toString());
    const confidence = calculateReflectionConfidence(quality, executionIndicators);

    return {
      reflected: patterns.length > 0 || quality.exact || quality.encoded,
      encodingType: encodingType as EncodingType | 'mixed',
      context,
      executionIndicators,
      confidence,
      encodingLevel,
    };
  }

  private async testReflectedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const reflectionProbe = await this.analyzeReflectionContext(page, surface, baseUrl, 'xss-reflection-probe');
    const reflectionContext = reflectionProbe?.context || 'none';
    const encoding = reflectionProbe?.encoding || 'none';
    const payloads = this.getContextAwarePayloads(surface, reflectionContext, encoding);

    for (const payload of payloads) {
      if (this.hasTestedPayload(surface, payload)) continue;

      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const reflectionAnalysis = this.analyzeReflection(result, payload);
        const confidence = this.calculateConfidence(XssType.REFLECTED, result, { reflectionAnalysis });

        this.markPayloadTested(surface, payload);

        if (reflectionAnalysis.reflected && confidence >= 0.7) {
          const vuln = this.createVulnerability(surface, result, XssType.REFLECTED, baseUrl, payload, {
            reflectionAnalysis,
            confidence,
          });

          if (confidence >= this.config.minConfidenceForEarlyExit) {
            return vuln;
          }

          return vuln;
        }
      } catch (error) {
        this.logger.warn(`Error testing reflected XSS with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private async testStoredXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const marker = `xss-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const storedPayload = `<script>window.__xss_mark__='${marker}';alert('XSS-STORED')</script>`;

    try {
      const result = await this.injector.inject(page, surface, storedPayload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
        baseUrl,
      });

      await page.waitForTimeout(500);
      await page.reload({ waitUntil: 'domcontentloaded' });

      const body = await page.content();
      const reflectionAnalysis = this.analyzeReflection(
        {
          ...result,
          response: { ...(result.response || {}), body },
        },
        storedPayload
      );

      const confidence = Math.max(0.95, this.calculateConfidence(XssType.STORED, result, { reflectionAnalysis }));

      if (body.includes(marker) || reflectionAnalysis.executionIndicators.length > 0 || reflectionAnalysis.reflected) {
        return this.createVulnerability(surface, result, XssType.STORED, baseUrl, storedPayload, {
          reflectionAnalysis,
          confidence,
        });
      }
    } catch (error) {
      this.logger.warn('Error testing stored XSS:', error);
    }

    return null;
  }

  private async testAngularTemplateInjection(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const uniqueMarker = randomBytes(6).toString('hex');
    const angularPayloads = [
      { payload: '{{13337*9999}}', expected: '133356663' },
      { payload: `{{'${uniqueMarker}'}}`, expected: uniqueMarker },
      { payload: '{{constructor.constructor("return 133356663")()}}', expected: '133356663' },
    ];

    const deadline = Date.now() + this.config.techniqueTimeouts.angularTemplate;

    for (const { payload, expected } of angularPayloads) {
      if (Date.now() > deadline) {
        this.stats.timeouts += 1;
        this.stats.timeoutsByTechnique[XssType.ANGULAR_TEMPLATE] += 1;
        break;
      }

      if (this.hasTestedPayload(surface, payload)) continue;

      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const responseBody = result.response?.body || '';
        const domContent = await page.content();
        const evaluated = responseBody.includes(expected) || domContent.includes(expected);
        const literalPresent = responseBody.includes(payload) || domContent.includes(payload.replace(/\{\{|\}\}/g, ''));

        this.markPayloadTested(surface, payload);

        if (evaluated && !literalPresent) {
          const reflectionAnalysis = this.analyzeReflection(
            {
              ...result,
              response: { ...(result.response || {}), body: responseBody },
            },
            payload
          );

          const confidence = Math.max(0.8, this.calculateConfidence(XssType.ANGULAR_TEMPLATE, result, { reflectionAnalysis }));

          return this.createVulnerability(surface, result, XssType.ANGULAR_TEMPLATE, baseUrl, payload, {
            reflectionAnalysis,
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn(`Error testing Angular template injection with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private isPayloadUnescapedInJson(result: InjectionResult, payload: string): boolean {
    const body = result.response?.body || '';

    try {
      const json = JSON.parse(body);
      const jsonStr = JSON.stringify(json);

      if (jsonStr.includes(payload)) {
        const escaped = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
        return !jsonStr.includes(escaped);
      }
    } catch (e) {
      return body.includes(payload);
    }

    return false;
  }

  private async testJsonXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const jsonPayloads = [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '"><script>alert("XSS")</script>',
      '\"><img src=x onerror=alert("XSS")>',
    ];

    for (const payload of jsonPayloads) {
      if (this.hasTestedPayload(surface, payload)) continue;
      try {
        const result = await this.injector.inject(page, surface, payload, {
          encoding: PayloadEncoding.NONE,
          submit: true,
          baseUrl,
        });

        const unescaped = this.isPayloadUnescapedInJson(result, payload);
        const confidence = this.calculateConfidence(XssType.JSON_XSS, result, {
          reflectionAnalysis: this.analyzeReflection(result, payload),
          encodingBypassed: unescaped,
        });

        this.markPayloadTested(surface, payload);

        if (unescaped && confidence >= 0.7) {
          return this.createVulnerability(surface, result, XssType.JSON_XSS, baseUrl, payload, {
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn(`Error testing JSON XSS with payload ${payload}: ${error}`);
      }
    }

    return null;
  }

  private async testDomBasedXss(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const domPayloads = [
      '#<script>alert("DOM-XSS")</script>',
      '#<img src=x onerror=alert("DOM-XSS")>',
      'javascript:alert("DOM-XSS")',
      'data:text/html,<script>alert("DOM-XSS")</script>',
    ];

    const deadline = Date.now() + this.config.techniqueTimeouts.domBased;

    for (const payload of domPayloads) {
      if (Date.now() > deadline) {
        this.stats.timeouts += 1;
        this.stats.timeoutsByTechnique[XssType.DOM_BASED] += 1;
        break;
      }

      if (this.hasTestedPayload(surface, payload)) continue;

      let consoleListener: ((msg: any) => void) | null = null;

      try {
        const dialogPromise = new Promise<boolean>((resolve) => {
          const listener = (dialog: any) => {
            dialog.dismiss().catch(() => {});
            page.off('dialog', listener);
            resolve(true);
          };
          page.on('dialog', listener);
          setTimeout(() => {
            page.off('dialog', listener);
            resolve(false);
          }, 1000);
        });

        if (surface.type === AttackSurfaceType.URL_PARAMETER || surface.type === AttackSurfaceType.LINK) {
          await page.goto(`${baseUrl}${payload}`);
        } else {
          await this.injector.inject(page, surface, payload, {
            encoding: PayloadEncoding.NONE,
            submit: true,
            baseUrl,
          });
        }

        const dialogDetected = await dialogPromise;
        const domContent = await page.content();
        const consoleErrors: string[] = [];
        consoleListener = (msg: any) => {
          if (msg.type() === 'error') {
            consoleErrors.push(msg.text());
          }
        };
        page.on('console', consoleListener);

        const domResult: InjectionResult = {
          payload,
          encoding: PayloadEncoding.NONE,
          strategy: 0 as any,
          surface,
          response: {
            url: `${baseUrl}${payload}`,
            status: 200,
            body: domContent,
            headers: {},
            timing: 0,
          },
        };

        const reflectionAnalysis = this.analyzeReflection(domResult, payload);

        this.markPayloadTested(surface, payload);

        if (dialogDetected || reflectionAnalysis.executionIndicators.length > 0 || consoleErrors.length > 0) {
          const confidence = Math.max(
            0.85,
            this.calculateConfidence(XssType.DOM_BASED, domResult, {
              reflectionAnalysis,
              executionIndicators: reflectionAnalysis.executionIndicators,
            })
          );
          return this.createVulnerability(surface, domResult, XssType.DOM_BASED, baseUrl, payload, {
            reflectionAnalysis,
            executionIndicators: reflectionAnalysis.executionIndicators,
            confidence,
          });
        }
      } catch (error) {
        this.logger.warn('Error testing DOM-based XSS:', error);
      } finally {
        if (consoleListener) {
          page.off('console', consoleListener);
        }
      }
    }

    return null;
  }

  private getTechniqueConfidence(technique: XssType): number {
    switch (technique) {
      case XssType.STORED:
        return 0.95;
      case XssType.REFLECTED:
        return 0.9;
      case XssType.DOM_BASED:
        return 0.85;
      case XssType.ANGULAR_TEMPLATE:
        return 0.8;
      case XssType.JSON_XSS:
        return 0.75;
      default:
        return 0.5;
    }
  }

  private calculateConfidence(
    technique: XssType,
    _result: InjectionResult,
    additionalData?: {
      reflectionAnalysis?: any;
      executionIndicators?: string[];
      encodingBypassed?: boolean;
    }
  ): number {
    let confidence = this.getTechniqueConfidence(technique);

    if (additionalData?.reflectionAnalysis) {
      const { reflected, encodingType, executionIndicators } = additionalData.reflectionAnalysis;

      if (reflected && encodingType === 'none' && executionIndicators.length > 0) {
        confidence = Math.min(1, confidence + 0.1);
      }

      if (encodingType !== 'none' && !additionalData.encodingBypassed) {
        confidence *= 0.5;
      }
    }

    if (additionalData?.executionIndicators && additionalData.executionIndicators.length > 2) {
      confidence = Math.min(1, confidence + 0.05);
    }

    return confidence;
  }

  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const reflectionAnalysis = this.analyzeReflection(result, result.payload);
    if (reflectionAnalysis.reflected) {
      const confidence = this.calculateConfidence(XssType.REFLECTED, result, { reflectionAnalysis });
      const vuln = this.createVulnerability(result.surface, result, XssType.REFLECTED, result.response?.url || '', result.payload, {
        reflectionAnalysis,
        confidence,
      });
      vulnerabilities.push(vuln);
    }
    return vulnerabilities;
  }

  async validate(): Promise<boolean> {
    return true;
  }

  getPayloads(): string[] {
    return [
      '<script>alert("XSS")</script>',
      '<img src=x onerror=alert("XSS")>',
      '<svg onload=alert("XSS")>',
      '" onclick=alert("XSS") "',
      "' onfocus=alert('XSS') '",
      '"; alert("XSS"); //',
      'javascript:alert("XSS")',
      '<iframe src="javascript:alert(\'XSS\')">',
    ];
  }

  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    xssType: XssType,
    baseUrl: string,
    payload: string,
    additionalData?: {
      reflectionAnalysis?: any;
      executionIndicators?: string[];
      confidence?: number;
      encodingStatus?: string;
    }
  ): Vulnerability {
    const typeDescriptions = {
      [XssType.REFLECTED]: 'Reflected XSS - Payload is immediately reflected in the response',
      [XssType.STORED]: 'Stored XSS - Payload is stored and executed when page is viewed',
      [XssType.DOM_BASED]: 'DOM-based XSS - Payload is executed through client-side DOM manipulation',
      [XssType.ANGULAR_TEMPLATE]: 'Angular template injection leading to XSS',
      [XssType.JSON_XSS]: 'JSON XSS - Payload is reflected in JSON context',
    };

    const severityMap = {
      [XssType.REFLECTED]: VulnerabilitySeverity.HIGH,
      [XssType.STORED]: VulnerabilitySeverity.CRITICAL,
      [XssType.DOM_BASED]: VulnerabilitySeverity.HIGH,
      [XssType.ANGULAR_TEMPLATE]: VulnerabilitySeverity.HIGH,
      [XssType.JSON_XSS]: VulnerabilitySeverity.HIGH,
    };

    const confidence = additionalData?.confidence ?? this.getTechniqueConfidence(xssType);
    const cwe = 'CWE-79';
    const owasp = getOWASP2025Category(cwe) || 'A03:2021';

    return {
      id: `xss-${xssType}-${surface.name}-${Date.now()}`,
      title: `Cross-Site Scripting (${xssType})`,
      description: typeDescriptions[xssType] + ` in ${surface.type} '${surface.name}'`,
      severity: severityMap[xssType],
      category: VulnerabilityCategory.XSS,
      cwe,
      owasp,
      url: result.response?.url || baseUrl,
      evidence: {
        request: {
          body: payload,
          url: result.response?.url || baseUrl,
          method: (surface.metadata as any)?.method || 'GET',
        },
        response: {
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
          headers: result.response?.headers,
        },
        metadata: {
          technique: xssType,
          confidence,
          reflectionAnalysis: additionalData?.reflectionAnalysis,
          executionIndicators: additionalData?.executionIndicators,
          encodingStatus: additionalData?.encodingStatus,
          contextInfo: {
            surfaceType: surface.type,
            injectionContext: surface.context,
            inputType: surface.metadata?.inputType,
            reflectionContext: additionalData?.reflectionAnalysis?.context,
          },
          verificationStatus: 'unverified',
          payload,
          surfaceName: surface.name,
        },
      },
      remediation:
        'Properly encode/escape all user input before rendering in HTML. Use context-appropriate output encoding, implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies, validate input with allowlists, use modern frameworks with auto-escaping.',
      references: [
        'https://owasp.org/www-community/attacks/xss/',
        'https://cwe.mitre.org/data/definitions/79.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }

  public getStats(): XssDetectorStats {
    return JSON.parse(JSON.stringify(this.stats));
  }

  public getDetectionStatistics(): { totalAttempts: number; successRate: number; avgTimeouts: number } {
    const attempts = Object.values(this.stats.attempts).reduce((a, b) => a + b, 0);
    const timeouts = Object.values(this.stats.timeoutsByTechnique).reduce((a, b) => a + b, 0);
    const successRate = attempts ? this.stats.vulnsFound / attempts : 0;
    const avgTimeouts = attempts ? timeouts / attempts : 0;
    return { totalAttempts: attempts, successRate, avgTimeouts };
  }

  private logTechniqueStart(technique: XssType, surface: AttackSurface): void {
    this.logger.debug(`[XSS] Testing ${technique} on ${surface.name}`);
  }

  private logTechniqueResult(technique: XssType, success: boolean, duration: number): void {
    this.logger.debug(`[XSS] ${technique} ${success ? 'FOUND' : 'clean'} (${duration}ms)`);
  }
}
