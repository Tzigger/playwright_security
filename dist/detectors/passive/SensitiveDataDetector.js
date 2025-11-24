"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SensitiveDataDetector = void 0;
const enums_1 = require("../../types/enums");
const Logger_1 = require("../../utils/logger/Logger");
const cwe_mapping_1 = require("../../utils/cwe/cwe-mapping");
const sensitive_data_patterns_1 = require("../../utils/patterns/sensitive-data-patterns");
const uuid_1 = require("uuid");
class SensitiveDataDetector {
    logger;
    allPatterns = new Map();
    constructor() {
        this.logger = new Logger_1.Logger(enums_1.LogLevel.INFO, 'SensitiveDataDetector');
        this.initializePatterns();
    }
    initializePatterns() {
        this.allPatterns = new Map([
            ['API Keys', { patterns: sensitive_data_patterns_1.API_KEY_PATTERNS, category: 'API Keys', severity: enums_1.VulnerabilitySeverity.CRITICAL }],
            ['Passwords', { patterns: sensitive_data_patterns_1.PASSWORD_PATTERNS, category: 'Passwords', severity: enums_1.VulnerabilitySeverity.CRITICAL }],
            ['Private Keys', { patterns: sensitive_data_patterns_1.PRIVATE_KEY_PATTERNS, category: 'Private Keys', severity: enums_1.VulnerabilitySeverity.CRITICAL }],
            ['JWT Tokens', { patterns: sensitive_data_patterns_1.JWT_PATTERNS, category: 'JWT Tokens', severity: enums_1.VulnerabilitySeverity.HIGH }],
            ['Database Credentials', { patterns: sensitive_data_patterns_1.DB_CONNECTION_PATTERNS, category: 'Database Credentials', severity: enums_1.VulnerabilitySeverity.CRITICAL }],
            ['Credit Cards', { patterns: sensitive_data_patterns_1.CREDIT_CARD_PATTERNS, category: 'Credit Cards', severity: enums_1.VulnerabilitySeverity.HIGH }],
            ['SSN/CNP', { patterns: sensitive_data_patterns_1.SSN_PATTERNS, category: 'Personal Identifiers', severity: enums_1.VulnerabilitySeverity.HIGH }],
            ['Emails', { patterns: sensitive_data_patterns_1.EMAIL_PATTERNS, category: 'Email Addresses', severity: enums_1.VulnerabilitySeverity.MEDIUM }],
            ['Phone Numbers', { patterns: sensitive_data_patterns_1.PHONE_PATTERNS, category: 'Phone Numbers', severity: enums_1.VulnerabilitySeverity.MEDIUM }],
        ]);
    }
    async detect(context) {
        this.logger.info('Starting sensitive data detection');
        const vulnerabilities = [];
        try {
            for (const response of context.responses) {
                if (!response.body) {
                    continue;
                }
                for (const [patternType, config] of this.allPatterns.entries()) {
                    const findings = this.scanForPatterns(response.body, config.patterns);
                    if (findings.length > 0) {
                        const vulnerability = this.createVulnerability(response, patternType, config.category, config.severity, findings);
                        vulnerabilities.push(vulnerability);
                    }
                }
            }
            for (const request of context.requests) {
                const requestVulns = await this.detectInRequest(request);
                vulnerabilities.push(...requestVulns);
            }
            this.logger.info(`Sensitive data detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    async detectInRequest(request) {
        const vulnerabilities = [];
        const urlFindings = [];
        for (const [patternType, config] of this.allPatterns.entries()) {
            const matches = this.scanForPatterns(request.url, config.patterns);
            if (matches.length > 0) {
                urlFindings.push(`${patternType}: ${matches.join(', ')}`);
            }
        }
        if (urlFindings.length > 0) {
            const vulnerability = {
                id: (0, uuid_1.v4)(),
                category: enums_1.VulnerabilityCategory.INFORMATION_DISCLOSURE,
                severity: enums_1.VulnerabilitySeverity.HIGH,
                title: 'Sensitive Data in URL',
                description: `Sensitive data detected in request URL: ${request.url}`,
                url: request.url,
                evidence: {
                    request: {
                        method: request.method,
                        url: request.url,
                        headers: request.headers,
                    },
                    source: 'PassiveScanner',
                    description: `Found: ${urlFindings.join('; ')}`,
                },
                remediation: 'Never include sensitive data in URLs. Use POST requests with encrypted body or secure headers.',
                references: [
                    'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                ],
                cwe: 'CWE-598',
                owasp: 'A01:2021 - Broken Access Control',
                timestamp: Date.now(),
            };
            const mappedVuln = (0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability);
            vulnerabilities.push(mappedVuln);
        }
        if (request.postData) {
            const postDataFindings = [];
            for (const [patternType, config] of this.allPatterns.entries()) {
                const matches = this.scanForPatterns(request.postData, config.patterns);
                if (matches.length > 0 && (patternType === 'Passwords' || patternType === 'Database Credentials')) {
                    postDataFindings.push(`${patternType}: ${matches.join(', ')}`);
                }
            }
            if (postDataFindings.length > 0) {
                const vulnerability = {
                    id: (0, uuid_1.v4)(),
                    category: enums_1.VulnerabilityCategory.BROKEN_AUTHENTICATION,
                    severity: enums_1.VulnerabilitySeverity.CRITICAL,
                    title: 'Credentials in Request Body',
                    description: 'Credentials detected in request body (verify if transmitted over HTTPS)',
                    url: request.url,
                    evidence: {
                        request: {
                            method: request.method,
                            url: request.url,
                            headers: request.headers,
                        },
                        source: 'PassiveScanner',
                        description: `Found: ${postDataFindings.join('; ')}`,
                    },
                    remediation: 'Ensure credentials are transmitted over HTTPS with proper encryption.',
                    references: ['https://owasp.org/www-project-web-security-testing-guide/'],
                    cwe: 'CWE-319',
                    owasp: 'A02:2021 - Cryptographic Failures',
                    timestamp: Date.now(),
                };
                const mappedVuln = (0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability);
                vulnerabilities.push(mappedVuln);
            }
        }
        return vulnerabilities;
    }
    scanForPatterns(text, patterns) {
        const findings = [];
        for (const pattern of patterns) {
            const matches = text.match(pattern);
            if (matches) {
                const redactedMatches = matches.map((match) => this.redactSensitiveData(match));
                findings.push(...redactedMatches);
            }
        }
        return [...new Set(findings)];
    }
    createVulnerability(response, patternType, category, severity, findings) {
        const vulnerability = {
            id: (0, uuid_1.v4)(),
            category: enums_1.VulnerabilityCategory.INFORMATION_DISCLOSURE,
            severity,
            title: `Sensitive Data Exposure: ${patternType}`,
            description: `Detected ${patternType.toLowerCase()} exposed in HTTP response from ${response.url}`,
            url: response.url,
            evidence: {
                response: {
                    status: response.status,
                    headers: response.headers,
                    snippet: response.body && findings[0] ? this.createSnippet(response.body, findings[0]) : undefined,
                },
                source: 'PassiveScanner',
                description: `Found ${findings.length} instance(s) of ${category}: ${findings.slice(0, 3).join(', ')}${findings.length > 3 ? '...' : ''}`,
            },
            remediation: this.getRemediation(patternType),
            references: [
                'https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure',
                'https://cwe.mitre.org/data/definitions/200.html',
            ],
            cwe: 'CWE-200',
            owasp: 'A02:2021 - Cryptographic Failures',
            timestamp: Date.now(),
        };
        return (0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability);
    }
    createSnippet(body, finding) {
        const index = body.indexOf(finding);
        if (index === -1) {
            return body.substring(0, 200);
        }
        const start = Math.max(0, index - 50);
        const end = Math.min(body.length, index + finding.length + 50);
        return '...' + body.substring(start, end) + '...';
    }
    redactSensitiveData(data) {
        if (data.length <= 8) {
            return '***REDACTED***';
        }
        return data.substring(0, 4) + '***' + data.substring(data.length - 4);
    }
    getRemediation(patternType) {
        const remediations = {
            'API Keys': 'Remove API keys from client-side code. Use environment variables and server-side authentication.',
            'Credentials': 'Never expose credentials in responses. Implement proper authentication and authorization.',
            'PII': 'Implement data minimization. Encrypt sensitive PII and ensure compliance with privacy regulations (GDPR, CCPA).',
            'Tokens': 'Use secure token storage (HttpOnly cookies). Implement token rotation and expiration.',
            'Secrets': 'Store secrets in secure vaults (HashiCorp Vault, AWS Secrets Manager). Never expose in client code.',
        };
        return remediations[patternType] || 'Review and remove sensitive data exposure.';
    }
    async validate() {
        for (const [type, config] of this.allPatterns.entries()) {
            if (config.patterns.length === 0) {
                this.logger.warn(`No patterns defined for ${type}`);
                return false;
            }
        }
        return true;
    }
    getPatterns() {
        const allPatterns = [];
        for (const config of this.allPatterns.values()) {
            allPatterns.push(...config.patterns);
        }
        return allPatterns;
    }
}
exports.SensitiveDataDetector = SensitiveDataDetector;
//# sourceMappingURL=SensitiveDataDetector.js.map