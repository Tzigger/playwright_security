"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.InsecureTransmissionDetector = void 0;
const enums_1 = require("../../types/enums");
const Logger_1 = require("../../utils/logger/Logger");
const cwe_mapping_1 = require("../../utils/cwe/cwe-mapping");
const uuid_1 = require("uuid");
class InsecureTransmissionDetector {
    logger;
    sensitiveParamNames = [
        'password',
        'passwd',
        'pwd',
        'secret',
        'token',
        'api_key',
        'apikey',
        'access_token',
        'auth',
        'session',
        'ssn',
        'credit_card',
        'cc',
        'cvv',
        'pin',
    ];
    constructor() {
        this.logger = new Logger_1.Logger(enums_1.LogLevel.INFO, 'InsecureTransmissionDetector');
    }
    async detect(context) {
        this.logger.info('Starting insecure transmission detection');
        const vulnerabilities = [];
        try {
            for (const request of context.requests) {
                if (request.method === enums_1.HttpMethod.GET) {
                    const urlVulns = this.detectSensitiveDataInUrl(request);
                    vulnerabilities.push(...urlVulns);
                }
                if (!this.isHttps(request.url)) {
                    const httpVulns = this.detectNonHttpsTransmission(request);
                    vulnerabilities.push(...httpVulns);
                }
            }
            const mixedContentVulns = this.detectMixedContent(context.requests);
            vulnerabilities.push(...mixedContentVulns);
            this.logger.info(`Insecure transmission detection completed. Found ${vulnerabilities.length} issues`);
        }
        catch (error) {
            this.logger.error(`Error during detection: ${error}`);
        }
        return vulnerabilities;
    }
    detectSensitiveDataInUrl(request) {
        const vulnerabilities = [];
        try {
            const url = new URL(request.url);
            const params = url.searchParams;
            const sensitiveParams = [];
            params.forEach((_value, key) => {
                if (this.isSensitiveParameter(key)) {
                    sensitiveParams.push(key);
                }
            });
            if (sensitiveParams.length > 0) {
                const vulnerability = {
                    id: (0, uuid_1.v4)(),
                    category: enums_1.VulnerabilityCategory.INSECURE_COMMUNICATION,
                    severity: enums_1.VulnerabilitySeverity.HIGH,
                    title: 'Sensitive Data in URL Parameters',
                    description: `Sensitive parameters detected in GET request URL: ${sensitiveParams.join(', ')}`,
                    url: request.url,
                    evidence: {
                        request: {
                            method: request.method,
                            url: request.url,
                            headers: request.headers,
                        },
                        source: 'PassiveScanner',
                        description: `Parameters: ${sensitiveParams.join(', ')}. URLs with sensitive data can be logged in browser history, server logs, and referrer headers.`,
                    },
                    remediation: 'Never transmit sensitive data via GET parameters. Use POST requests with encrypted body. Implement proper session management.',
                    references: [
                        'https://owasp.org/www-community/vulnerabilities/Information_exposure_through_query_strings_in_url',
                        'https://cwe.mitre.org/data/definitions/598.html',
                    ],
                    cwe: 'CWE-598',
                    owasp: 'A02:2021 - Cryptographic Failures',
                    timestamp: Date.now(),
                };
                vulnerabilities.push((0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability));
            }
        }
        catch (error) {
            this.logger.debug(`Failed to parse URL: ${request.url}`);
        }
        return vulnerabilities;
    }
    detectNonHttpsTransmission(request) {
        const vulnerabilities = [];
        const hasSensitiveData = request.postData && this.containsSensitiveKeywords(request.postData);
        const shouldFlag = hasSensitiveData ||
            request.method === enums_1.HttpMethod.POST ||
            request.resourceType === 'document';
        if (shouldFlag) {
            const vulnerability = {
                id: (0, uuid_1.v4)(),
                category: enums_1.VulnerabilityCategory.INSECURE_COMMUNICATION,
                severity: enums_1.VulnerabilitySeverity.CRITICAL,
                title: 'Insecure HTTP Transmission',
                description: `Data transmitted over unencrypted HTTP connection to ${request.url}`,
                url: request.url,
                evidence: {
                    request: {
                        method: request.method,
                        url: request.url,
                        headers: request.headers,
                    },
                    source: 'PassiveScanner',
                    description: `${request.method} request sent over HTTP. All data is transmitted in plaintext and can be intercepted.`,
                },
                remediation: 'Implement HTTPS across the entire application. Redirect all HTTP traffic to HTTPS. Use HSTS headers to enforce HTTPS.',
                references: [
                    'https://owasp.org/www-community/controls/SecureFlag',
                    'https://cwe.mitre.org/data/definitions/319.html',
                ],
                cwe: 'CWE-319',
                owasp: 'A02:2021 - Cryptographic Failures',
                timestamp: Date.now(),
            };
            vulnerabilities.push((0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability));
        }
        return vulnerabilities;
    }
    detectMixedContent(requests) {
        const vulnerabilities = [];
        const httpsPage = requests.find((r) => r.resourceType === 'document' && this.isHttps(r.url));
        if (!httpsPage) {
            return vulnerabilities;
        }
        const httpResources = requests.filter((r) => !this.isHttps(r.url) && r.resourceType !== 'document');
        if (httpResources.length > 0) {
            const resourceTypes = [...new Set(httpResources.map((r) => r.resourceType))];
            const vulnerability = {
                id: (0, uuid_1.v4)(),
                category: enums_1.VulnerabilityCategory.INSECURE_COMMUNICATION,
                severity: enums_1.VulnerabilitySeverity.MEDIUM,
                title: 'Mixed Content Detected',
                description: `HTTPS page loading ${httpResources.length} HTTP resources (${resourceTypes.join(', ')})`,
                url: httpsPage.url,
                evidence: {
                    request: {
                        method: httpsPage.method,
                        url: httpsPage.url,
                    },
                    source: 'PassiveScanner',
                    description: `HTTP resources: ${httpResources.slice(0, 5).map((r) => r.url).join(', ')}${httpResources.length > 5 ? '...' : ''}`,
                },
                remediation: 'Load all resources over HTTPS. Update resource URLs to use HTTPS or protocol-relative URLs. Configure Content-Security-Policy to block mixed content.',
                references: [
                    'https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content',
                    'https://cwe.mitre.org/data/definitions/311.html',
                ],
                cwe: 'CWE-311',
                owasp: 'A02:2021 - Cryptographic Failures',
                timestamp: Date.now(),
            };
            vulnerabilities.push((0, cwe_mapping_1.mapVulnerabilityToCWE)(vulnerability));
        }
        return vulnerabilities;
    }
    isHttps(url) {
        return url.startsWith('https://');
    }
    isSensitiveParameter(paramName) {
        const lowerParam = paramName.toLowerCase();
        return this.sensitiveParamNames.some((sensitive) => lowerParam.includes(sensitive));
    }
    containsSensitiveKeywords(text) {
        const lowerText = text.toLowerCase();
        return this.sensitiveParamNames.some((keyword) => lowerText.includes(keyword));
    }
    async validate() {
        return this.sensitiveParamNames.length > 0;
    }
    getPatterns() {
        return [];
    }
}
exports.InsecureTransmissionDetector = InsecureTransmissionDetector;
//# sourceMappingURL=InsecureTransmissionDetector.js.map