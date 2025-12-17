/**
 * ApiScanner - Direct REST/GraphQL API Security Testing
 * 
 * Scans APIs directly without relying on form elements.
 * Tests endpoints discovered by ApiEndpointDiscovery.
 * 
 * Features:
 * - Direct HTTP request injection
 * - GraphQL introspection and mutation testing
 * - Authentication bypass testing
 * - IDOR/BOLA detection
 * - Parameter tampering
 * - Mass assignment testing
 * 
 * @module scanners/active/ApiScanner
 */

import { EventEmitter } from 'events';
import { BrowserContext, APIRequestContext } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel, VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';
import { PayloadFilter } from '../../utils/PayloadFilter';

// Type alias for backwards compatibility
type SeverityLevel = VulnerabilitySeverity;
const SeverityLevel = VulnerabilitySeverity;
import { Vulnerability } from '../../types/vulnerability';
import { 
  ApiEndpoint, 
  ApiType, 
  ApiParameter, 
  ParameterLocation 
} from './ApiEndpointDiscovery';

/**
 * Test category
 */
export enum ApiTestCategory {
  SQL_INJECTION = 'sqli',
  XSS = 'xss',
  IDOR = 'idor',
  AUTH_BYPASS = 'auth-bypass',
  MASS_ASSIGNMENT = 'mass-assignment',
  RATE_LIMITING = 'rate-limiting',
  GRAPHQL = 'graphql',
  PARAMETER_TAMPERING = 'param-tampering',
  NOSQL_INJECTION = 'nosql',
}

/**
 * Test result
 */
export interface ApiTestResult {
  endpoint: ApiEndpoint;
  category: ApiTestCategory;
  payload: string;
  vulnerable: boolean;
  severity?: SeverityLevel;
  response?: {
    status: number;
    body: string;
    headers: Record<string, string>;
    timing: number;
  };
  evidence?: string;
  confidence: number;
}

/**
 * Scanner configuration
 */
export interface ApiScannerConfig {
  enabledCategories: ApiTestCategory[];
  maxPayloadsPerEndpoint: number;
  timeout: number;
  followRedirects: boolean;
  includeAuthTests: boolean;
  includeGraphQLTests: boolean;
  rateLimit: number; // Requests per second
}

const DEFAULT_CONFIG: ApiScannerConfig = {
  enabledCategories: [
    ApiTestCategory.SQL_INJECTION,
    ApiTestCategory.XSS,
    ApiTestCategory.IDOR,
    ApiTestCategory.AUTH_BYPASS,
    ApiTestCategory.NOSQL_INJECTION,
  ],
  maxPayloadsPerEndpoint: 20,
  timeout: 15000,
  followRedirects: true,
  includeAuthTests: true,
  includeGraphQLTests: true,
  rateLimit: 10,
};

/**
 * SQL Injection payloads for API testing
 */
const SQL_PAYLOADS = [
  "' OR '1'='1",
  "' OR '1'='1' --",
  "admin'--",
  "1' OR '1'='1",
  "' UNION SELECT NULL--",
  "'; DROP TABLE users--",
  "1; SELECT * FROM users--",
  "' AND 1=1--",
  "' AND 1=2--",
  "' AND SLEEP(5)--",
];

/**
 * XSS payloads for API testing
 */
const XSS_PAYLOADS = [
  "<script>alert(1)</script>",
  "<img src=x onerror=alert(1)>",
  "<svg/onload=alert(1)>",
  '"><script>alert(1)</script>',
  "javascript:alert(1)",
  "{{constructor.constructor('alert(1)')()}}",
];

/**
 * NoSQL injection payloads
 */
const NOSQL_PAYLOADS = [
  '{"$gt": ""}',
  '{"$ne": ""}',
  '{"$regex": ".*"}',
  "true, $where: '1 == 1'",
  "'; return true; var a='",
  '{"$where": "1 == 1"}',
];

/**
 * IDOR payloads (ID manipulation)
 */
const IDOR_VARIATIONS = [
  (_id: string) => String(parseInt(_id) + 1),
  (_id: string) => String(parseInt(_id) - 1),
  (_id: string) => '1',
  (_id: string) => '0',
  (_id: string) => '-1',
  (_id: string) => _id.replace(/./g, '0'),
];

/**
 * GraphQL introspection query
 */
const GRAPHQL_INTROSPECTION = `
  query IntrospectionQuery {
    __schema {
      queryType { name }
      mutationType { name }
      types {
        name
        fields {
          name
          args { name type { name } }
        }
      }
    }
  }
`;

/**
 * ApiScanner Class
 * 
 * Directly tests API endpoints for security vulnerabilities
 */
export class ApiScanner extends EventEmitter {
  private logger: Logger;
  private config: ApiScannerConfig;
  private vulnerabilities: Vulnerability[] = [];
  private testedEndpoints: Set<string> = new Set();
  private requestContext: APIRequestContext | null = null;
  private payloadFilter: PayloadFilter;
  private safeMode: boolean = false;

  constructor(config: Partial<ApiScannerConfig> = {}, logLevel: LogLevel = LogLevel.INFO, safeMode: boolean = false) {
    super();
    this.logger = new Logger(logLevel, 'ApiScanner');
    this.config = { ...DEFAULT_CONFIG, ...config };
    this.payloadFilter = new PayloadFilter(logLevel);
    this.safeMode = safeMode;
    
    if (this.safeMode) {
      this.logger.info('SafeMode ENABLED: Destructive payloads will be filtered');
    }
  }

  /**
   * Set safe mode
   */
  public setSafeMode(enabled: boolean): void {
    this.safeMode = enabled;
    if (this.safeMode) {
      this.logger.info('SafeMode ENABLED: Destructive payloads will be filtered');
    } else {
      this.logger.warn('SafeMode DISABLED: All payloads will be used');
    }
  }

  /**
   * Initialize scanner with browser context
   */
  public async initialize(context: BrowserContext): Promise<void> {
    // Create API request context from browser context for authenticated requests
    this.requestContext = context.request;
    this.logger.info('ApiScanner initialized');
  }

  /**
   * Scan a single endpoint
   */
  public async scanEndpoint(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];
    const endpointKey = `${endpoint.method}:${endpoint.url}`;

    if (this.testedEndpoints.has(endpointKey)) {
      this.logger.debug(`Skipping already tested endpoint: ${endpointKey}`);
      return results;
    }

    this.testedEndpoints.add(endpointKey);
    this.logger.info(`Scanning endpoint: ${endpoint.method} ${endpoint.path}`);

    // Test each enabled category
    for (const category of this.config.enabledCategories) {
      try {
        const categoryResults = await this.testCategory(endpoint, category);
        results.push(...categoryResults);
      } catch (error) {
        this.logger.warn(`Error testing ${category} on ${endpoint.path}: ${error}`);
      }

      // Rate limiting
      await this.delay(1000 / this.config.rateLimit);
    }

    // GraphQL-specific tests
    if (endpoint.type === ApiType.GRAPHQL && this.config.includeGraphQLTests) {
      const gqlResults = await this.testGraphQL(endpoint);
      results.push(...gqlResults);
    }

    return results;
  }

  /**
   * Scan multiple endpoints
   */
  public async scanEndpoints(endpoints: ApiEndpoint[]): Promise<Vulnerability[]> {
    this.vulnerabilities = [];
    const totalResults: ApiTestResult[] = [];

    for (const endpoint of endpoints) {
      const results = await this.scanEndpoint(endpoint);
      totalResults.push(...results);

      // Convert positive results to vulnerabilities
      const vulns = results
        .filter(r => r.vulnerable)
        .map(r => this.resultToVulnerability(r));
      
      this.vulnerabilities.push(...vulns);
    }

    this.logger.info(`Scan complete. Found ${this.vulnerabilities.length} vulnerabilities`);
    return this.vulnerabilities;
  }

  /**
   * Test a specific category on an endpoint
   */
  private async testCategory(
    endpoint: ApiEndpoint,
    category: ApiTestCategory
  ): Promise<ApiTestResult[]> {
    switch (category) {
      case ApiTestCategory.SQL_INJECTION:
        return this.testSqlInjection(endpoint);
      case ApiTestCategory.XSS:
        return this.testXss(endpoint);
      case ApiTestCategory.IDOR:
        return this.testIdor(endpoint);
      case ApiTestCategory.AUTH_BYPASS:
        return this.testAuthBypass(endpoint);
      case ApiTestCategory.NOSQL_INJECTION:
        return this.testNoSqlInjection(endpoint);
      case ApiTestCategory.MASS_ASSIGNMENT:
        return this.testMassAssignment(endpoint);
      default:
        return [];
    }
  }

  /**
   * Test for SQL injection
   */
  private async testSqlInjection(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];
    const params = this.getTestableParams(endpoint);
    
    // Apply safe mode filtering
    const payloads = this.safeMode 
      ? this.payloadFilter.filterPayloads(SQL_PAYLOADS)
      : SQL_PAYLOADS;

    for (const param of params) {
      for (const payload of payloads.slice(0, this.config.maxPayloadsPerEndpoint)) {
        const result = await this.injectPayload(endpoint, param, payload, ApiTestCategory.SQL_INJECTION);
        
        if (result && this.detectSqlInjection(result)) {
          results.push({
            endpoint,
            category: ApiTestCategory.SQL_INJECTION,
            payload,
            vulnerable: true,
            severity: SeverityLevel.CRITICAL,
            response: result,
            evidence: this.extractSqlEvidence(result.body),
            confidence: 0.85,
          });
        }
      }
    }

    return results;
  }

  /**
   * Test for XSS in API responses
   */
  private async testXss(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];
    const params = this.getTestableParams(endpoint);

    for (const param of params) {
      for (const payload of XSS_PAYLOADS.slice(0, this.config.maxPayloadsPerEndpoint)) {
        const result = await this.injectPayload(endpoint, param, payload, ApiTestCategory.XSS);
        
        if (result && this.detectXssInResponse(result, payload)) {
          results.push({
            endpoint,
            category: ApiTestCategory.XSS,
            payload,
            vulnerable: true,
            severity: SeverityLevel.HIGH,
            response: result,
            evidence: `Payload reflected in response: ${payload}`,
            confidence: 0.80,
          });
        }
      }
    }

    return results;
  }

  /**
   * Test for IDOR/BOLA
   */
  private async testIdor(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];
    const idParams = endpoint.parameters.filter(p => 
      p.name.toLowerCase().includes('id') ||
      p.location === ParameterLocation.PATH
    );

    for (const param of idParams) {
      const originalValue = String(param.example || '1');
      
      for (const variationFn of IDOR_VARIATIONS) {
        const newValue = variationFn(originalValue);
        const result = await this.injectPayload(endpoint, param, newValue, ApiTestCategory.IDOR);
        
        if (result && this.detectIdor(result, originalValue)) {
          results.push({
            endpoint,
            category: ApiTestCategory.IDOR,
            payload: newValue,
            vulnerable: true,
            severity: SeverityLevel.HIGH,
            response: result,
            evidence: `Access to resource with modified ID: ${newValue}`,
            confidence: 0.70,
          });
        }
      }
    }

    return results;
  }

  /**
   * Test for authentication bypass
   */
  private async testAuthBypass(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];

    // Only test authenticated endpoints
    if (!endpoint.authentication) {
      return results;
    }

    // Test without authentication
    const unauthResult = await this.makeRequest(
      endpoint,
      endpoint.requestBody?.example,
      { skipAuth: true }
    );

    if (unauthResult && unauthResult.status >= 200 && unauthResult.status < 300) {
      results.push({
        endpoint,
        category: ApiTestCategory.AUTH_BYPASS,
        payload: 'No authentication',
        vulnerable: true,
        severity: SeverityLevel.CRITICAL,
        response: unauthResult,
        evidence: `Endpoint accessible without authentication (status: ${unauthResult.status})`,
        confidence: 0.90,
      });
    }

    // Test with invalid token
    const invalidTokenResult = await this.makeRequest(
      endpoint,
      endpoint.requestBody?.example,
      { customHeaders: { 'Authorization': 'Bearer invalid_token_12345' } }
    );

    if (invalidTokenResult && invalidTokenResult.status >= 200 && invalidTokenResult.status < 300) {
      results.push({
        endpoint,
        category: ApiTestCategory.AUTH_BYPASS,
        payload: 'Invalid bearer token',
        vulnerable: true,
        severity: SeverityLevel.HIGH,
        response: invalidTokenResult,
        evidence: 'Endpoint accepts invalid authentication token',
        confidence: 0.85,
      });
    }

    return results;
  }

  /**
   * Test for NoSQL injection
   */
  private async testNoSqlInjection(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];
    const params = this.getTestableParams(endpoint);
    
    // Apply safe mode filtering
    const payloads = this.safeMode 
      ? this.payloadFilter.filterPayloads(NOSQL_PAYLOADS)
      : NOSQL_PAYLOADS;

    for (const param of params) {
      for (const payload of payloads) {
        const result = await this.injectPayload(endpoint, param, payload, ApiTestCategory.NOSQL_INJECTION);
        
        if (result && this.detectNoSqlInjection(result)) {
          results.push({
            endpoint,
            category: ApiTestCategory.NOSQL_INJECTION,
            payload,
            vulnerable: true,
            severity: SeverityLevel.HIGH,
            response: result,
            evidence: 'NoSQL injection indicators detected',
            confidence: 0.75,
          });
        }
      }
    }

    return results;
  }

  /**
   * Test for mass assignment
   */
  private async testMassAssignment(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];

    // Only test POST/PUT/PATCH endpoints
    if (!['POST', 'PUT', 'PATCH'].includes(endpoint.method)) {
      return results;
    }

    // Add sensitive fields that shouldn't be assignable
    const sensitiveFields = ['role', 'isAdmin', 'admin', 'permissions', 'balance', 'credits'];
    
    for (const field of sensitiveFields) {
      const maliciousBody = {
        ...(endpoint.requestBody?.example || {}),
        [field]: true,
      };

      const result = await this.makeRequest(endpoint, maliciousBody);
      
      if (result && result.status >= 200 && result.status < 300) {
        // Check if the field was accepted
        if (result.body.includes(field)) {
          results.push({
            endpoint,
            category: ApiTestCategory.MASS_ASSIGNMENT,
            payload: JSON.stringify({ [field]: true }),
            vulnerable: true,
            severity: SeverityLevel.MEDIUM,
            response: result,
            evidence: `Sensitive field "${field}" may be assignable`,
            confidence: 0.65,
          });
        }
      }
    }

    return results;
  }

  /**
   * Test GraphQL endpoint
   */
  private async testGraphQL(endpoint: ApiEndpoint): Promise<ApiTestResult[]> {
    const results: ApiTestResult[] = [];

    // Test introspection (should often be disabled in production)
    const introspectionResult = await this.makeRequest(endpoint, {
      query: GRAPHQL_INTROSPECTION,
    });

    if (introspectionResult && introspectionResult.body.includes('__schema')) {
      results.push({
        endpoint,
        category: ApiTestCategory.GRAPHQL,
        payload: 'Introspection query',
        vulnerable: true,
        severity: SeverityLevel.LOW,
        response: introspectionResult,
        evidence: 'GraphQL introspection is enabled',
        confidence: 0.95,
      });
    }

    // Test for batching attacks
    const batchResult = await this.makeRequest(endpoint, [
      { query: '{ __typename }' },
      { query: '{ __typename }' },
      { query: '{ __typename }' },
    ]);

    if (batchResult && batchResult.status === 200) {
      results.push({
        endpoint,
        category: ApiTestCategory.GRAPHQL,
        payload: 'Batch queries',
        vulnerable: true,
        severity: SeverityLevel.LOW,
        response: batchResult,
        evidence: 'GraphQL batching is enabled (potential for DoS)',
        confidence: 0.70,
      });
    }

    return results;
  }

  /**
   * Inject payload into parameter
   */
  private async injectPayload(
    endpoint: ApiEndpoint,
    param: ApiParameter,
    payload: string,
    _category: ApiTestCategory
  ): Promise<{ status: number; body: string; headers: Record<string, string>; timing: number } | null> {
    let body = endpoint.requestBody?.example || {};
    let url = endpoint.url;
    const headers: Record<string, string> = {};

    switch (param.location) {
      case ParameterLocation.BODY:
        // Inject into body
        body = this.setNestedValue(body, param.name, payload);
        break;
      case ParameterLocation.QUERY:
        // Inject into query string
        const urlObj = new URL(url);
        urlObj.searchParams.set(param.name, payload);
        url = urlObj.toString();
        break;
      case ParameterLocation.PATH:
        // Inject into path
        url = url.replace(new RegExp(`{${param.name}|${param.example}`), payload);
        break;
      case ParameterLocation.HEADER:
        headers[param.name] = payload;
        break;
    }

    return this.makeRequest({ ...endpoint, url }, body, { customHeaders: headers });
  }

  /**
   * Make HTTP request
   */
  private async makeRequest(
    endpoint: ApiEndpoint,
    body?: any,
    options: { skipAuth?: boolean; customHeaders?: Record<string, string> } = {}
  ): Promise<{ status: number; body: string; headers: Record<string, string>; timing: number } | null> {
    if (!this.requestContext) {
      this.logger.warn('Request context not initialized');
      return null;
    }

    const startTime = Date.now();

    try {
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        ...options.customHeaders,
      };

      // Remove auth if testing bypass
      if (options.skipAuth && endpoint.authentication) {
        delete headers['Authorization'];
        delete headers['Cookie'];
      }

      const response = await this.requestContext.fetch(endpoint.url, {
        method: endpoint.method,
        headers,
        data: body ? JSON.stringify(body) : undefined,
        timeout: this.config.timeout,
      });

      const responseBody = await response.text();
      const responseHeaders: Record<string, string> = {};
      const headersObj = response.headers();
      for (const key of Object.keys(headersObj)) {
        responseHeaders[key.toLowerCase()] = headersObj[key] || '';
      }

      return {
        status: response.status(),
        body: responseBody,
        headers: responseHeaders,
        timing: Date.now() - startTime,
      };

    } catch (error) {
      this.logger.debug(`Request failed: ${error}`);
      return null;
    }
  }

  // Detection methods

  private detectSqlInjection(response: { status: number; body: string }): boolean {
    const sqlErrors = [
      /sql.*syntax/i,
      /mysql.*error/i,
      /postgresql.*error/i,
      /ora-\d+/i,
      /sqlite.*error/i,
      /unclosed quotation/i,
      /syntax error.*sql/i,
      /SQLSTATE/i,
    ];

    return sqlErrors.some(pattern => pattern.test(response.body));
  }

  private extractSqlEvidence(body: string): string {
    const patterns = [
      /SQL.*?error[^<]*/i,
      /mysql[^<]*/i,
      /syntax.*?near[^<]*/i,
    ];

    for (const pattern of patterns) {
      const match = body.match(pattern);
      if (match) {
        return match[0].substring(0, 200);
      }
    }
    return 'SQL error pattern detected';
  }

  private detectXssInResponse(response: { body: string }, payload: string): boolean {
    // Check for unencoded reflection
    if (response.body.includes(payload)) {
      // Verify it's not encoded
      const encoded = payload.replace(/</g, '&lt;').replace(/>/g, '&gt;');
      return !response.body.includes(encoded) || response.body.includes(payload);
    }
    return false;
  }

  private detectIdor(response: { status: number; body: string }, _originalId: string): boolean {
    // Successful access with different ID
    return response.status >= 200 && response.status < 300 && 
           response.body.length > 50;  // Non-empty meaningful response
  }

  private detectNoSqlInjection(response: { status: number; body: string }): boolean {
    const nosqlIndicators = [
      /unexpected token/i,
      /invalid bson/i,
      /mongodb/i,
      /\$where.*not.*allowed/i,
    ];

    return nosqlIndicators.some(pattern => pattern.test(response.body)) ||
           (response.status === 200 && response.body.includes('"$'));
  }

  // Helper methods

  private getTestableParams(endpoint: ApiEndpoint): ApiParameter[] {
    return endpoint.parameters.filter(p => !p.sensitive && p.type === 'string');
  }

  private setNestedValue(obj: any, path: string, value: any): any {
    const result = { ...obj };
    const parts = path.split('.');
    let current = result;

    for (let i = 0; i < parts.length - 1; i++) {
      const part = parts[i];
      if (part === undefined) continue;
      if (!current[part]) {
        current[part] = {};
      }
      current = current[part];
    }

    const lastPart = parts[parts.length - 1];
    if (lastPart !== undefined) {
      current[lastPart] = value;
    }
    return result;
  }

  private resultToVulnerability(result: ApiTestResult): Vulnerability {
    return {
      id: `api-${result.category}-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      category: this.mapCategory(result.category),
      title: this.getCategoryTitle(result.category),
      description: result.evidence || `${result.category} vulnerability detected`,
      severity: result.severity || VulnerabilitySeverity.MEDIUM,
      url: result.endpoint.url,
      evidence: {
        request: {
          method: result.endpoint.method,
          url: result.endpoint.url,
        },
        response: result.response ? {
          status: result.response.status,
          body: result.response.body.substring(0, 500),
        } : undefined,
      },
      remediation: this.getRemediation(result.category),
      confidence: result.confidence,
      timestamp: new Date(),
      references: [],
      metadata: {
        detectedBy: 'ApiScanner',
        endpoint: result.endpoint.path,
        timestamp: new Date().toISOString(),
        payload: result.payload,
      },
    };
  }

  private mapCategory(category: string): VulnerabilityCategory {
    const categoryMap: Record<string, VulnerabilityCategory> = {
      'sql-injection': VulnerabilityCategory.INJECTION,
      'xss': VulnerabilityCategory.XSS,
      'idor': VulnerabilityCategory.AUTHORIZATION,
      'auth-bypass': VulnerabilityCategory.AUTHENTICATION,
      'nosql-injection': VulnerabilityCategory.INJECTION,
      'graphql': VulnerabilityCategory.INJECTION,
      'mass-assignment': VulnerabilityCategory.INJECTION,
      'rate-limiting': VulnerabilityCategory.CONFIGURATION,
    };
    return categoryMap[category] || VulnerabilityCategory.INJECTION;
  }

  private getCategoryTitle(category: ApiTestCategory): string {
    const titles: Record<ApiTestCategory, string> = {
      [ApiTestCategory.SQL_INJECTION]: 'SQL Injection in API',
      [ApiTestCategory.XSS]: 'Cross-Site Scripting in API Response',
      [ApiTestCategory.IDOR]: 'Insecure Direct Object Reference (IDOR)',
      [ApiTestCategory.AUTH_BYPASS]: 'Authentication Bypass',
      [ApiTestCategory.MASS_ASSIGNMENT]: 'Mass Assignment Vulnerability',
      [ApiTestCategory.RATE_LIMITING]: 'Missing Rate Limiting',
      [ApiTestCategory.GRAPHQL]: 'GraphQL Security Issue',
      [ApiTestCategory.PARAMETER_TAMPERING]: 'Parameter Tampering',
      [ApiTestCategory.NOSQL_INJECTION]: 'NoSQL Injection',
    };
    return titles[category];
  }

  private getRemediation(category: ApiTestCategory): string {
    const remediations: Record<ApiTestCategory, string> = {
      [ApiTestCategory.SQL_INJECTION]: 'Use parameterized queries and input validation.',
      [ApiTestCategory.XSS]: 'Encode output and implement Content-Security-Policy.',
      [ApiTestCategory.IDOR]: 'Implement proper authorization checks for all resources.',
      [ApiTestCategory.AUTH_BYPASS]: 'Enforce authentication on all sensitive endpoints.',
      [ApiTestCategory.MASS_ASSIGNMENT]: 'Use DTOs and whitelist allowed fields.',
      [ApiTestCategory.RATE_LIMITING]: 'Implement rate limiting and request throttling.',
      [ApiTestCategory.GRAPHQL]: 'Disable introspection in production, implement query depth limiting.',
      [ApiTestCategory.PARAMETER_TAMPERING]: 'Validate all input parameters server-side.',
      [ApiTestCategory.NOSQL_INJECTION]: 'Use parameterized queries and sanitize input.',
    };
    return remediations[category];
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get all detected vulnerabilities
   */
  public getVulnerabilities(): Vulnerability[] {
    return [...this.vulnerabilities];
  }

  /**
   * Clear state
   */
  public clear(): void {
    this.vulnerabilities = [];
    this.testedEndpoints.clear();
  }
}
