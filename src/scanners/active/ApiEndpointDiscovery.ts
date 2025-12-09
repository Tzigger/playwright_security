/**
 * ApiEndpointDiscovery - Automatic API Endpoint Detection
 * 
 * Discovers REST and GraphQL API endpoints by analyzing network traffic.
 * Creates an attack surface map from observed API calls.
 * 
 * Features:
 * - Captures API calls from network traffic
 * - Detects RESTful patterns
 * - Identifies GraphQL endpoints
 * - Extracts parameters and authentication tokens
 * - Builds comprehensive API map for testing
 * 
 * @module scanners/active/ApiEndpointDiscovery
 */

import { EventEmitter } from 'events';
import { Page, Request, Response } from 'playwright';
import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { AttackSurface, AttackSurfaceType, InjectionContext } from './DomExplorer';

/**
 * HTTP Methods
 */
export type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE' | 'OPTIONS' | 'HEAD';

/**
 * API Type
 */
export enum ApiType {
  REST = 'rest',
  GRAPHQL = 'graphql',
  SOAP = 'soap',
  JSONRPC = 'json-rpc',
  WEBSOCKET = 'websocket',
  UNKNOWN = 'unknown',
}

/**
 * Parameter location
 */
export enum ParameterLocation {
  PATH = 'path',
  QUERY = 'query',
  BODY = 'body',
  HEADER = 'header',
  COOKIE = 'cookie',
}

/**
 * Discovered API parameter
 */
export interface ApiParameter {
  name: string;
  location: ParameterLocation;
  type: 'string' | 'number' | 'boolean' | 'array' | 'object' | 'unknown';
  required: boolean;
  example?: string | number | boolean;
  sensitive?: boolean; // e.g., password, token, key
}

/**
 * Discovered API endpoint
 */
export interface ApiEndpoint {
  id: string;
  url: string;
  baseUrl: string;
  path: string;
  method: HttpMethod;
  type: ApiType;
  parameters: ApiParameter[];
  headers: Record<string, string>;
  requestBody?: {
    contentType: string;
    schema?: Record<string, any>;
    example?: any;
  };
  response?: {
    status: number;
    contentType: string;
    bodySize: number;
  };
  authentication?: {
    type: 'bearer' | 'basic' | 'apiKey' | 'cookie' | 'custom';
    location: 'header' | 'query' | 'cookie';
    parameterName: string;
  };
  metadata: {
    discoveredAt: number;
    callCount: number;
    lastCalled: number;
  };
}

/**
 * GraphQL operation
 */
export interface GraphQLOperation {
  type: 'query' | 'mutation' | 'subscription';
  name?: string;
  query: string;
  variables?: Record<string, any>;
}

/**
 * Discovery configuration
 */
export interface ApiDiscoveryConfig {
  captureRequests: boolean;
  captureResponses: boolean;
  detectPatterns: boolean;
  extractParameters: boolean;
  maxBodySize: number;
  excludePatterns: RegExp[];
  includePatterns: RegExp[];
}

const DEFAULT_CONFIG: ApiDiscoveryConfig = {
  captureRequests: true,
  captureResponses: true,
  detectPatterns: true,
  extractParameters: true,
  maxBodySize: 1024 * 1024, // 1MB
  excludePatterns: [
    /\.(css|js|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?.*)?$/i,
    /^data:/,
    /google-analytics|gtag|facebook|twitter|analytics|tracking/i,
  ],
  includePatterns: [
    /\/api\//i,
    /\/rest\//i,
    /\/graphql/i,
    /\/v\d+\//i,
    /\.(json|xml)$/i,
  ],
};

/**
 * ApiEndpointDiscovery Class
 * 
 * Discovers and catalogs API endpoints from network traffic
 * for comprehensive security testing.
 */
export class ApiEndpointDiscovery extends EventEmitter {
  private logger: Logger;
  private config: ApiDiscoveryConfig;
  private endpoints: Map<string, ApiEndpoint> = new Map();
  private graphqlOperations: Map<string, GraphQLOperation[]> = new Map();
  private page: Page | null = null;
  private isListening: boolean = false;

  constructor(config: Partial<ApiDiscoveryConfig> = {}, logLevel: LogLevel = LogLevel.INFO) {
    super();
    this.logger = new Logger(logLevel, 'ApiEndpointDiscovery');
    this.config = { ...DEFAULT_CONFIG, ...config };
  }

  /**
   * Start listening to network traffic
   */
  public async startDiscovery(page: Page): Promise<void> {
    if (this.isListening) {
      this.logger.warn('Discovery already running');
      return;
    }

    this.page = page;
    this.isListening = true;

    // Listen to requests
    page.on('request', this.handleRequest.bind(this));
    page.on('response', this.handleResponse.bind(this));

    this.logger.info('API endpoint discovery started');
  }

  /**
   * Stop listening to network traffic
   */
  public stopDiscovery(): void {
    if (!this.isListening || !this.page) {
      return;
    }

    this.page.removeListener('request', this.handleRequest.bind(this));
    this.page.removeListener('response', this.handleResponse.bind(this));
    
    this.isListening = false;
    this.logger.info(`API discovery stopped. Found ${this.endpoints.size} endpoints`);
  }

  /**
   * Handle intercepted request
   */
  private async handleRequest(request: Request): Promise<void> {
    const url = request.url();

    // Check exclusions
    if (this.shouldExclude(url)) {
      return;
    }

    const method = request.method() as HttpMethod;
    const endpointId = this.generateEndpointId(url, method);

    // Check if endpoint already exists
    if (this.endpoints.has(endpointId)) {
      // Update call count
      const endpoint = this.endpoints.get(endpointId)!;
      endpoint.metadata.callCount++;
      endpoint.metadata.lastCalled = Date.now();
      return;
    }

    try {
      const endpoint = await this.parseRequest(request);
      this.endpoints.set(endpointId, endpoint);
      
      this.logger.debug(`Discovered endpoint: ${method} ${endpoint.path}`);
      this.emit('endpoint-discovered', endpoint);

    } catch (error) {
      this.logger.debug(`Failed to parse request: ${error}`);
    }
  }

  /**
   * Handle intercepted response
   */
  private async handleResponse(response: Response): Promise<void> {
    const request = response.request();
    const url = request.url();
    const method = request.method() as HttpMethod;
    const endpointId = this.generateEndpointId(url, method);

    const endpoint = this.endpoints.get(endpointId);
    if (!endpoint) {
      return;
    }

    try {
      endpoint.response = {
        status: response.status(),
        contentType: response.headers()['content-type'] || 'unknown',
        bodySize: parseInt(response.headers()['content-length'] || '0', 10),
      };

      // Detect API type from response if not already set
      if (endpoint.type === ApiType.UNKNOWN) {
        endpoint.type = this.detectApiType(response);
      }

    } catch (error) {
      this.logger.debug(`Failed to parse response: ${error}`);
    }
  }

  /**
   * Parse request into ApiEndpoint
   */
  private async parseRequest(request: Request): Promise<ApiEndpoint> {
    const url = new URL(request.url());
    const method = request.method() as HttpMethod;
    const headers = request.headers();

    const endpoint: ApiEndpoint = {
      id: this.generateEndpointId(request.url(), method),
      url: request.url(),
      baseUrl: url.origin,
      path: url.pathname,
      method,
      type: this.detectApiTypeFromRequest(request),
      parameters: [],
      headers: this.filterSensitiveHeaders(headers),
      metadata: {
        discoveredAt: Date.now(),
        callCount: 1,
        lastCalled: Date.now(),
      },
    };

    // Extract query parameters
    url.searchParams.forEach((value, name) => {
      endpoint.parameters.push({
        name,
        location: ParameterLocation.QUERY,
        type: this.inferType(value),
        required: false,
        example: value,
        sensitive: this.isSensitiveParameter(name),
      });
    });

    // Extract path parameters (e.g., /users/{id})
    const pathParams = this.extractPathParameters(url.pathname);
    endpoint.parameters.push(...pathParams);

    // Extract body parameters
    if (['POST', 'PUT', 'PATCH'].includes(method)) {
      const postData = request.postData();
      if (postData) {
        const contentType = headers['content-type'] || '';
        const bodyParams = this.extractBodyParameters(postData, contentType);
        endpoint.parameters.push(...bodyParams);
        
        // Store request body info
        endpoint.requestBody = {
          contentType,
          example: this.safeParseJson(postData),
        };

        // Check for GraphQL
        if (endpoint.type === ApiType.GRAPHQL) {
          this.extractGraphQLOperations(request.url(), postData);
        }
      }
    }

    // Detect authentication
    endpoint.authentication = this.detectAuthentication(headers, url);

    return endpoint;
  }

  /**
   * Detect API type from request
   */
  private detectApiTypeFromRequest(request: Request): ApiType {
    const url = request.url().toLowerCase();
    const headers = request.headers();
    const postData = request.postData();

    // GraphQL detection
    if (url.includes('graphql') || url.includes('/gql')) {
      return ApiType.GRAPHQL;
    }
    if (postData && postData.includes('"query"') && (postData.includes('query ') || postData.includes('mutation '))) {
      return ApiType.GRAPHQL;
    }

    // SOAP detection
    if (headers['content-type']?.includes('soap') || 
        headers['content-type']?.includes('xml') && postData?.includes('Envelope')) {
      return ApiType.SOAP;
    }

    // JSON-RPC detection
    if (postData && postData.includes('"jsonrpc"')) {
      return ApiType.JSONRPC;
    }

    // REST (default for API-like URLs)
    if (url.includes('/api/') || url.includes('/rest/') || url.includes('/v1/') || url.includes('/v2/')) {
      return ApiType.REST;
    }

    return ApiType.UNKNOWN;
  }

  /**
   * Detect API type from response
   */
  private detectApiType(response: Response): ApiType {
    const contentType = response.headers()['content-type'] || '';
    
    if (contentType.includes('json')) {
      return ApiType.REST;
    }
    if (contentType.includes('xml')) {
      return ApiType.SOAP;
    }

    return ApiType.UNKNOWN;
  }

  /**
   * Extract path parameters from URL pattern
   */
  private extractPathParameters(path: string): ApiParameter[] {
    const params: ApiParameter[] = [];
    const segments = path.split('/');

    segments.forEach((segment, index) => {
      // Check for UUID-like patterns
      if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(segment)) {
        params.push({
          name: `pathParam${index}`,
          location: ParameterLocation.PATH,
          type: 'string',
          required: true,
          example: segment,
          sensitive: false,
        });
      }
      // Check for numeric IDs
      else if (/^\d+$/.test(segment) && parseInt(segment) > 0) {
        params.push({
          name: `id`,
          location: ParameterLocation.PATH,
          type: 'number',
          required: true,
          example: parseInt(segment),
          sensitive: false,
        });
      }
      // Check for MongoDB ObjectIds
      else if (/^[0-9a-f]{24}$/i.test(segment)) {
        params.push({
          name: `objectId`,
          location: ParameterLocation.PATH,
          type: 'string',
          required: true,
          example: segment,
          sensitive: false,
        });
      }
    });

    return params;
  }

  /**
   * Extract body parameters
   */
  private extractBodyParameters(body: string, contentType: string): ApiParameter[] {
    const params: ApiParameter[] = [];

    if (contentType.includes('json')) {
      try {
        const parsed = JSON.parse(body);
        this.extractJsonParameters(parsed, params, '');
      } catch {
        // Not valid JSON
      }
    } else if (contentType.includes('x-www-form-urlencoded')) {
      const urlParams = new URLSearchParams(body);
      urlParams.forEach((value, name) => {
        params.push({
          name,
          location: ParameterLocation.BODY,
          type: this.inferType(value),
          required: false,
          example: value,
          sensitive: this.isSensitiveParameter(name),
        });
      });
    }

    return params;
  }

  /**
   * Recursively extract parameters from JSON
   */
  private extractJsonParameters(
    obj: any, 
    params: ApiParameter[], 
    prefix: string
  ): void {
    if (obj === null || obj === undefined) {
      return;
    }

    if (typeof obj !== 'object') {
      return;
    }

    for (const [key, value] of Object.entries(obj)) {
      const paramName = prefix ? `${prefix}.${key}` : key;
      
      if (value === null || value === undefined) {
        params.push({
          name: paramName,
          location: ParameterLocation.BODY,
          type: 'unknown',
          required: false,
          sensitive: this.isSensitiveParameter(key),
        });
      } else if (Array.isArray(value)) {
        params.push({
          name: paramName,
          location: ParameterLocation.BODY,
          type: 'array',
          required: false,
          example: value.length > 0 ? value[0] : undefined,
          sensitive: this.isSensitiveParameter(key),
        });
        // Recursively extract from first element
        if (value.length > 0 && typeof value[0] === 'object') {
          this.extractJsonParameters(value[0], params, `${paramName}[]`);
        }
      } else if (typeof value === 'object') {
        params.push({
          name: paramName,
          location: ParameterLocation.BODY,
          type: 'object',
          required: false,
          sensitive: this.isSensitiveParameter(key),
        });
        this.extractJsonParameters(value, params, paramName);
      } else {
        // Value is a primitive type (string, number, boolean, or null)
        const primitiveValue = typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean'
          ? value
          : undefined;
        params.push({
          name: paramName,
          location: ParameterLocation.BODY,
          type: this.inferType(value),
          required: false,
          example: primitiveValue,
          sensitive: this.isSensitiveParameter(key),
        });
      }
    }
  }

  /**
   * Extract GraphQL operations
   */
  private extractGraphQLOperations(url: string, body: string): void {
    try {
      const parsed = JSON.parse(body);
      const operations: GraphQLOperation[] = [];

      if (parsed.query) {
        const queryMatch = parsed.query.match(/^\s*(query|mutation|subscription)\s+(\w+)?/);
        operations.push({
          type: (queryMatch?.[1] as GraphQLOperation['type']) || 'query',
          name: queryMatch?.[2] || parsed.operationName,
          query: parsed.query,
          variables: parsed.variables,
        });
      }

      // Handle batched queries
      if (Array.isArray(parsed)) {
        parsed.forEach(op => {
          if (op.query) {
            const queryMatch = op.query.match(/^\s*(query|mutation|subscription)\s+(\w+)?/);
            operations.push({
              type: (queryMatch?.[1] as GraphQLOperation['type']) || 'query',
              name: queryMatch?.[2] || op.operationName,
              query: op.query,
              variables: op.variables,
            });
          }
        });
      }

      if (operations.length > 0) {
        const existing = this.graphqlOperations.get(url) || [];
        this.graphqlOperations.set(url, [...existing, ...operations]);
        
        operations.forEach(op => {
          this.logger.debug(`GraphQL ${op.type}: ${op.name || 'anonymous'}`);
          this.emit('graphql-operation', op, url);
        });
      }

    } catch (error) {
      this.logger.debug(`Failed to parse GraphQL: ${error}`);
    }
  }

  /**
   * Detect authentication method
   */
  private detectAuthentication(
    headers: Record<string, string>,
    url: URL
  ): ApiEndpoint['authentication'] | undefined {
    // Bearer token
    const authHeader = headers['authorization'] || headers['Authorization'];
    if (authHeader) {
      if (authHeader.toLowerCase().startsWith('bearer')) {
        return {
          type: 'bearer',
          location: 'header',
          parameterName: 'Authorization',
        };
      }
      if (authHeader.toLowerCase().startsWith('basic')) {
        return {
          type: 'basic',
          location: 'header',
          parameterName: 'Authorization',
        };
      }
    }

    // API Key in header
    const apiKeyHeaders = ['x-api-key', 'api-key', 'apikey', 'x-auth-token'];
    for (const header of apiKeyHeaders) {
      if (headers[header] || headers[header.toLowerCase()]) {
        return {
          type: 'apiKey',
          location: 'header',
          parameterName: header,
        };
      }
    }

    // API Key in query
    const apiKeyParams = ['api_key', 'apikey', 'key', 'token', 'access_token'];
    for (const param of apiKeyParams) {
      if (url.searchParams.has(param)) {
        return {
          type: 'apiKey',
          location: 'query',
          parameterName: param,
        };
      }
    }

    // Cookie auth
    if (headers['cookie']?.includes('session') || headers['cookie']?.includes('auth')) {
      return {
        type: 'cookie',
        location: 'cookie',
        parameterName: 'session',
      };
    }

    return undefined;
  }

  /**
   * Convert endpoint to AttackSurface for compatibility
   */
  public endpointToAttackSurface(endpoint: ApiEndpoint): AttackSurface {
    return {
      id: endpoint.id,
      type: AttackSurfaceType.API_PARAM,
      name: `${endpoint.method} ${endpoint.path}`,
      context: InjectionContext.JSON,
      metadata: {
        url: endpoint.url,
        method: endpoint.method,
        apiType: endpoint.type,
        parameters: endpoint.parameters,
        authentication: endpoint.authentication,
      },
    };
  }

  /**
   * Get all discovered endpoints
   */
  public getEndpoints(): ApiEndpoint[] {
    return Array.from(this.endpoints.values());
  }

  /**
   * Get endpoints by type
   */
  public getEndpointsByType(type: ApiType): ApiEndpoint[] {
    return this.getEndpoints().filter(e => e.type === type);
  }

  /**
   * Get endpoints by method
   */
  public getEndpointsByMethod(method: HttpMethod): ApiEndpoint[] {
    return this.getEndpoints().filter(e => e.method === method);
  }

  /**
   * Get authenticated endpoints
   */
  public getAuthenticatedEndpoints(): ApiEndpoint[] {
    return this.getEndpoints().filter(e => e.authentication !== undefined);
  }

  /**
   * Get GraphQL operations
   */
  public getGraphQLOperations(): Map<string, GraphQLOperation[]> {
    return this.graphqlOperations;
  }

  /**
   * Get attack surfaces for all endpoints
   */
  public getAttackSurfaces(): AttackSurface[] {
    return this.getEndpoints().map(e => this.endpointToAttackSurface(e));
  }

  /**
   * Clear discovered data
   */
  public clear(): void {
    this.endpoints.clear();
    this.graphqlOperations.clear();
  }

  /**
   * Generate summary of discovered APIs
   */
  public getSummary(): {
    totalEndpoints: number;
    byType: Record<ApiType, number>;
    byMethod: Record<string, number>;
    authenticated: number;
    graphqlOperations: number;
  } {
    const endpoints = this.getEndpoints();
    const byType: Record<ApiType, number> = {
      [ApiType.REST]: 0,
      [ApiType.GRAPHQL]: 0,
      [ApiType.SOAP]: 0,
      [ApiType.JSONRPC]: 0,
      [ApiType.WEBSOCKET]: 0,
      [ApiType.UNKNOWN]: 0,
    };
    const byMethod: Record<string, number> = {};

    endpoints.forEach(e => {
      byType[e.type]++;
      byMethod[e.method] = (byMethod[e.method] || 0) + 1;
    });

    let totalGqlOps = 0;
    this.graphqlOperations.forEach(ops => totalGqlOps += ops.length);

    return {
      totalEndpoints: endpoints.length,
      byType,
      byMethod,
      authenticated: endpoints.filter(e => e.authentication).length,
      graphqlOperations: totalGqlOps,
    };
  }

  // Helper methods

  private generateEndpointId(url: string, method: HttpMethod): string {
    const parsed = new URL(url);
    const normalizedPath = this.normalizePath(parsed.pathname);
    return `${method}:${parsed.origin}${normalizedPath}`;
  }

  private normalizePath(path: string): string {
    // Replace UUIDs with placeholder
    path = path.replace(/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/gi, '{uuid}');
    // Replace numeric IDs with placeholder
    path = path.replace(/\/\d+(?=\/|$)/g, '/{id}');
    // Replace MongoDB ObjectIds
    path = path.replace(/[0-9a-f]{24}/gi, '{objectId}');
    return path;
  }

  private shouldExclude(url: string): boolean {
    // Check exclusions
    for (const pattern of this.config.excludePatterns) {
      if (pattern.test(url)) {
        return true;
      }
    }

    // If include patterns are defined, URL must match at least one
    if (this.config.includePatterns.length > 0) {
      const matches = this.config.includePatterns.some(pattern => pattern.test(url));
      return !matches;
    }

    return false;
  }

  private filterSensitiveHeaders(headers: Record<string, string>): Record<string, string> {
    const filtered: Record<string, string> = {};
    const sensitiveHeaders = ['authorization', 'cookie', 'x-api-key', 'x-auth-token'];
    
    for (const [key, value] of Object.entries(headers)) {
      if (sensitiveHeaders.includes(key.toLowerCase())) {
        filtered[key] = '[REDACTED]';
      } else {
        filtered[key] = value;
      }
    }
    
    return filtered;
  }

  private inferType(value: any): ApiParameter['type'] {
    if (typeof value === 'number') return 'number';
    if (typeof value === 'boolean') return 'boolean';
    if (Array.isArray(value)) return 'array';
    if (typeof value === 'object' && value !== null) return 'object';
    
    // String type inference
    if (typeof value === 'string') {
      if (/^\d+$/.test(value)) return 'number';
      if (value === 'true' || value === 'false') return 'boolean';
    }
    
    return 'string';
  }

  private isSensitiveParameter(name: string): boolean {
    const sensitivePatterns = [
      /password/i, /passwd/i, /secret/i, /token/i, /api[-_]?key/i,
      /auth/i, /credential/i, /private/i, /ssn/i, /credit/i,
    ];
    return sensitivePatterns.some(p => p.test(name));
  }

  private safeParseJson(str: string): any {
    try {
      return JSON.parse(str);
    } catch {
      return str;
    }
  }
}
