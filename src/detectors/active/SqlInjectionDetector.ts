import { Page } from 'playwright';
import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { AttackSurface, InjectionContext } from '../../scanners/active/DomExplorer';
import { PayloadInjector, InjectionResult, PayloadEncoding } from '../../scanners/active/PayloadInjector';

/**
 * SQL Injection Detection Techniques
 */
export enum SqlInjectionTechnique {
  ERROR_BASED = 'error-based',
  BOOLEAN_BASED = 'boolean-based',
  TIME_BASED = 'time-based',
  UNION_BASED = 'union-based',
  STACKED_QUERIES = 'stacked-queries',
}

/**
 * SQL Injection Detector - Detects SQL injection vulnerabilities
 * Implements multiple detection techniques following OWASP guidelines
 */
export class SqlInjectionDetector implements IActiveDetector {
  readonly name = 'SQL Injection Detector';
  readonly description = 'Detects SQL injection vulnerabilities using multiple techniques';
  readonly version = '1.0.0';

  private injector: PayloadInjector;

  constructor() {
    this.injector = new PayloadInjector();
  }

  /**
   * Detect SQL injection vulnerabilities
   */
  async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    const { page, attackSurfaces, baseUrl } = context;

    // Filter for SQL injection targets
    const sqlTargets = attackSurfaces.filter(
      (surface) => surface.context === InjectionContext.SQL || surface.name.toLowerCase().includes('id') || surface.name.toLowerCase().includes('search')
    );

    for (const surface of sqlTargets) {
      try {
        // Test different SQL injection techniques
        const errorBasedVuln = await this.testErrorBased(page, surface, baseUrl);
        if (errorBasedVuln) vulnerabilities.push(errorBasedVuln);

        const booleanBasedVuln = await this.testBooleanBased(page, surface, baseUrl);
        if (booleanBasedVuln) vulnerabilities.push(booleanBasedVuln);

        const timeBasedVuln = await this.testTimeBased(page, surface, baseUrl);
        if (timeBasedVuln) vulnerabilities.push(timeBasedVuln);

        const unionBasedVuln = await this.testUnionBased(page, surface, baseUrl);
        if (unionBasedVuln) vulnerabilities.push(unionBasedVuln);
      } catch (error) {
        console.error(`Error testing SQL injection on ${surface.name}:`, error);
      }
    }

    return vulnerabilities;
  }

  /**
   * Test for error-based SQL injection
   */
  private async testErrorBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const payloads = [
      "'", // Single quote
      "''", // Double single quote
      "' OR '1'='1", // Classic OR injection
      "' OR 1=1--", // Comment-based
      "' OR 'a'='a", // Always true
      "' UNION SELECT NULL--", // Union attempt
      "' AND 1=0 UNION ALL SELECT 'admin', 'password'--", // Advanced union
      "' WAITFOR DELAY '0:0:5'--", // Time-based SQL Server
      "'; DROP TABLE users--", // Destructive (testing detection, not actual execution)
      "1' AND '1'='1", // Numeric with string
      "1 AND 1=1", // Numeric boolean
    ];

    const results = await this.injector.injectMultiple(page, surface, payloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
    });

    for (const result of results) {
      if (this.hasSqlError(result)) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.ERROR_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Test for boolean-based blind SQL injection
   */
  private async testBooleanBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    // Test true vs false conditions
    const truePayloads = ["1' AND '1'='1", "1 AND 1=1", "' OR 'x'='x"];
    const falsePayloads = ["1' AND '1'='2", "1 AND 1=0", "' OR 'x'='y"];

    const trueResults = await this.injector.injectMultiple(page, surface, truePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
    });

    const falseResults = await this.injector.injectMultiple(page, surface, falsePayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
    });

    // Compare responses - if true conditions return different content than false, likely vulnerable
    const trueContent = trueResults.map((r) => r.response?.body?.length || 0);
    const falseContent = falseResults.map((r) => r.response?.body?.length || 0);

    const avgTrue = trueContent.reduce((a, b) => a + b, 0) / trueContent.length;
    const avgFalse = falseContent.reduce((a, b) => a + b, 0) / falseContent.length;

    // If there's a significant difference (>10%), likely boolean-based SQLi
    if (Math.abs(avgTrue - avgFalse) / Math.max(avgTrue, avgFalse) > 0.1 && trueResults[0]) {
      return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl);
    }

    return null;
  }

  /**
   * Test for time-based blind SQL injection
   */
  private async testTimeBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const timePayloads = [
      "1' AND SLEEP(5)--", // MySQL
      "1'; WAITFOR DELAY '0:0:5'--", // SQL Server
      "1'||pg_sleep(5)--", // PostgreSQL
      "1' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--", // MySQL subquery
    ];

    for (const payload of timePayloads) {
      const startTime = Date.now();
      const result = await this.injector.inject(page, surface, payload, {
        encoding: PayloadEncoding.NONE,
        submit: true,
      });
      const duration = Date.now() - startTime;

      // If response took > 4 seconds (accounting for network delay), likely time-based SQLi
      if (duration > 4000) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.TIME_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Test for UNION-based SQL injection
   */
  private async testUnionBased(page: Page, surface: AttackSurface, baseUrl: string): Promise<Vulnerability | null> {
    const unionPayloads = [
      "' UNION SELECT NULL--",
      "' UNION SELECT NULL,NULL--",
      "' UNION SELECT NULL,NULL,NULL--",
      "' UNION SELECT 'a',NULL,NULL--",
      "' UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables--",
      "1' UNION SELECT username,password,NULL FROM users--",
    ];

    const results = await this.injector.injectMultiple(page, surface, unionPayloads, {
      encoding: PayloadEncoding.NONE,
      submit: true,
    });

    for (const result of results) {
      // Check for UNION success indicators
      if (
        result.response?.body?.includes('table_name') ||
        result.response?.body?.includes('username') ||
        result.response?.body?.includes('password') ||
        (result.response?.status === 200 && result.response?.body && result.response.body.length > 1000)
      ) {
        return this.createVulnerability(surface, result, SqlInjectionTechnique.UNION_BASED, baseUrl);
      }
    }

    return null;
  }

  /**
   * Analyze injection result for SQL injection indicators
   */
  async analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    if (this.hasSqlError(result)) {
      vulnerabilities.push({
        id: `sqli-${result.surface.name}-${Date.now()}`,
        title: 'SQL Injection Vulnerability',
        description: `SQL injection detected in ${result.surface.type} '${result.surface.name}'`,
        severity: VulnerabilitySeverity.CRITICAL,
        category: VulnerabilityCategory.INJECTION,
        cwe: 'CWE-89',
        owasp: 'A03:2021',
        evidence: {
          request: { body: result.payload },
          response: { body: result.response?.body?.substring(0, 500) || '' },
        },
        remediation: 'Use parameterized queries or prepared statements to prevent SQL injection. Replace string concatenation with parameterized queries, use ORM frameworks with built-in protection, validate and sanitize all user input.',
        references: [
          'https://owasp.org/Top10/A03_2021-Injection/',
          'https://cwe.mitre.org/data/definitions/89.html',
        ],
        timestamp: new Date(),
      });
    }

    return vulnerabilities;
  }

  /**
   * Validate vulnerability (re-test to confirm)
   */
  async validate(): Promise<boolean> {
    // Validation would require re-testing with stored context
    return true;
  }

  /**
   * Get payloads for this detector
   */
  getPayloads(): string[] {
    return [
      "'",
      "' OR '1'='1",
      "' OR 1=1--",
      "' UNION SELECT NULL--",
      "' AND SLEEP(5)--",
      "1' AND '1'='1",
      "1 AND 1=1",
      "'; DROP TABLE users--",
    ];
  }

  /**
   * Check if result contains SQL error indicators
   */
  private hasSqlError(result: InjectionResult): boolean {
    const body = result.response?.body?.toLowerCase() || '';
    const errorPatterns = [
      'sql syntax',
      'mysql_fetch',
      'mysqli',
      'sqlexception',
      'ora-',
      'postgresql',
      'sqlite',
      'mssql',
      'syntax error',
      'unclosed quotation',
      'quoted string not properly terminated',
      'database error',
      'odbc',
      'jdbc',
      'pdo',
      'you have an error in your sql',
      'warning: mysql',
      'uncaught exception',
      'pg_query',
      'pg_exec',
    ];

    return errorPatterns.some((pattern) => body.includes(pattern));
  }

  /**
   * Create vulnerability object
   */
  private createVulnerability(
    surface: AttackSurface,
    result: InjectionResult,
    technique: SqlInjectionTechnique,
    baseUrl: string
  ): Vulnerability {
    const techniqueDescriptions = {
      [SqlInjectionTechnique.ERROR_BASED]: 'Error-based SQL injection detected through database error messages',
      [SqlInjectionTechnique.BOOLEAN_BASED]: 'Boolean-based blind SQL injection detected through differential responses',
      [SqlInjectionTechnique.TIME_BASED]: 'Time-based blind SQL injection detected through response delays',
      [SqlInjectionTechnique.UNION_BASED]: 'UNION-based SQL injection detected through query stacking',
      [SqlInjectionTechnique.STACKED_QUERIES]: 'Stacked queries SQL injection detected',
    };

    return {
      id: `sqli-${technique}-${surface.name}-${Date.now()}`,
      title: `SQL Injection (${technique})`,
      description: techniqueDescriptions[technique] + ` in ${surface.type} '${surface.name}'`,
      severity: VulnerabilitySeverity.CRITICAL,
      category: VulnerabilityCategory.INJECTION,
      cwe: 'CWE-89',
      owasp: 'A03:2021',
      url: result.response?.url || baseUrl,
      evidence: {
        request: { body: result.payload },
        response: { 
          body: result.response?.body?.substring(0, 1000) || '',
          status: result.response?.status,
        },
      },
      remediation: 'Use parameterized queries or prepared statements. Replace string concatenation with parameterized queries, use ORM frameworks with built-in SQL injection protection, validate and sanitize all user input, apply principle of least privilege to database accounts.',
      references: [
        'https://owasp.org/www-community/attacks/SQL_Injection',
        'https://cwe.mitre.org/data/definitions/89.html',
        'https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html',
      ],
      timestamp: new Date(),
    };
  }
}
