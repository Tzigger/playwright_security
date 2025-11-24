"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ErrorBasedDetector = exports.ErrorType = void 0;
const enums_1 = require("../../types/enums");
const PayloadInjector_1 = require("../../scanners/active/PayloadInjector");
var ErrorType;
(function (ErrorType) {
    ErrorType["DATABASE_ERROR"] = "database-error";
    ErrorType["STACK_TRACE"] = "stack-trace";
    ErrorType["EXCEPTION"] = "exception";
    ErrorType["DEBUG_INFO"] = "debug-info";
    ErrorType["PATH_DISCLOSURE"] = "path-disclosure";
})(ErrorType || (exports.ErrorType = ErrorType = {}));
class ErrorBasedDetector {
    name = 'Error-Based Information Disclosure Detector';
    description = 'Detects information disclosure through error messages, stack traces, and exceptions';
    version = '1.0.0';
    injector;
    constructor() {
        this.injector = new PayloadInjector_1.PayloadInjector();
    }
    async detect(context) {
        const vulnerabilities = [];
        const { page, attackSurfaces, baseUrl } = context;
        for (const surface of attackSurfaces) {
            try {
                const errorPayloads = this.getErrorTriggeringPayloads();
                for (const payload of errorPayloads) {
                    const result = await this.injector.inject(page, surface, payload, {
                        encoding: PayloadInjector_1.PayloadEncoding.NONE,
                        submit: true,
                    });
                    const errorVulns = await this.analyzeInjectionResult(result);
                    if (errorVulns.length > 0) {
                        vulnerabilities.push(...errorVulns);
                        break;
                    }
                }
            }
            catch (error) {
                console.error(`Error testing error disclosure on ${surface.name}:`, error);
            }
        }
        const existingErrors = await this.checkPageForErrors(page, baseUrl);
        vulnerabilities.push(...existingErrors);
        return vulnerabilities;
    }
    getErrorTriggeringPayloads() {
        return [
            '\x00',
            '%00',
            '§§§§§§§§',
            '../../../../etc/passwd',
            '..\\..\\..\\windows\\system32\\config\\sam',
            'A'.repeat(10000),
            '${7*7}',
            '{{7*7}}',
            '<%= 7*7 %>',
            '{invalid json',
            '<invalid><xml>',
            '[]',
            '{}',
            'NaN',
            'Infinity',
            'undefined',
            'null',
            '9999-99-99',
            '99999999999999999999',
            '-1',
            '; ls -la',
            '| whoami',
            '`id`',
            '*)(&',
            '*)(|',
            '{"$gt":""}',
            "' || '1'=='1",
        ];
    }
    async checkPageForErrors(page, baseUrl) {
        const vulnerabilities = [];
        try {
            const content = await page.content();
            const visibleText = await page.locator('body').innerText().catch(() => '');
            if (this.hasStackTrace(content)) {
                vulnerabilities.push(this.createVulnerability(ErrorType.STACK_TRACE, 'Stack Trace Disclosure', 'Application exposes stack traces in error responses', content, baseUrl));
            }
            if (this.hasDatabaseError(content)) {
                vulnerabilities.push(this.createVulnerability(ErrorType.DATABASE_ERROR, 'Database Error Disclosure', 'Application exposes database error messages', content, baseUrl));
            }
            if (this.hasPathDisclosure(content)) {
                vulnerabilities.push(this.createVulnerability(ErrorType.PATH_DISCLOSURE, 'Path Disclosure', 'Application exposes internal file system paths', content, baseUrl));
            }
            if (this.hasDebugInfo(visibleText)) {
                vulnerabilities.push(this.createVulnerability(ErrorType.DEBUG_INFO, 'Debug Information Disclosure', 'Application exposes debug information in production', visibleText, baseUrl));
            }
        }
        catch (error) {
            console.error('Error checking page for errors:', error);
        }
        return vulnerabilities;
    }
    hasStackTrace(content) {
        const stackTracePatterns = [
            /at\s+[\w$.]+\s*\([^)]+:\d+:\d+\)/i,
            /\s+at\s+[\w$.]+\.[a-zA-Z]+\([^)]+\)/i,
            /File\s+"[^"]+",\s+line\s+\d+/i,
            /in\s+\/[\w\/.-]+\s+on\s+line\s+\d+/i,
            /raise\s+\w+Error/i,
            /Traceback\s+\(most\s+recent\s+call\s+last\)/i,
            /Exception\s+in\s+thread/i,
            /Fatal error:/i,
            /Uncaught\s+(TypeError|ReferenceError|SyntaxError)/i,
            /System\.[\w.]+Exception:/i,
            /\w+Error:\s+.+\s+at\s+/i,
        ];
        return stackTracePatterns.some((pattern) => pattern.test(content));
    }
    hasDatabaseError(content) {
        const dbErrorPatterns = [
            /sql\s+syntax/i,
            /mysql_fetch_array\(\)/i,
            /pg_query\(\)/i,
            /sqlite3?_/i,
            /ORA-\d{5}/i,
            /SQL Server.*Error/i,
            /Microsoft.*ODBC.*Driver/i,
            /PostgreSQL.*ERROR/i,
            /MySQL.*Warning/i,
            /Database\s+connection\s+failed/i,
            /Could\s+not\s+connect\s+to\s+database/i,
            /mysqli?::query/i,
            /PDOException/i,
            /Doctrine\\DBAL/i,
            /InvalidQuery/i,
        ];
        return dbErrorPatterns.some((pattern) => pattern.test(content));
    }
    hasPathDisclosure(content) {
        const pathPatterns = [
            /[A-Z]:\\[\w\\.-]+/i,
            /\/home\/[\w\/.-]+/i,
            /\/var\/www\/[\w\/.-]+/i,
            /\/usr\/[\w\/.-]+/i,
            /\/opt\/[\w\/.-]+/i,
            /C:\\(Windows|Program Files|Users)/i,
            /\/Library\/[\w\/.-]+/i,
            /\/Applications\/[\w\/.-]+/i,
        ];
        return pathPatterns.some((pattern) => pattern.test(content));
    }
    hasDebugInfo(content) {
        const debugPatterns = [
            /DEBUG\s*[:=]\s*True/i,
            /\[DEBUG\]/i,
            /\[TRACE\]/i,
            /var_dump\s*\(/i,
            /print_r\s*\(/i,
            /console\.log\(/i,
            /System\.out\.println/i,
            /Debug Mode:\s*On/i,
            /<pre>[\s\S]*Array\s*\(/i,
            /X-Debug-Token/i,
            /Xdebug/i,
        ];
        return debugPatterns.some((pattern) => pattern.test(content));
    }
    async analyzeInjectionResult(result) {
        const vulnerabilities = [];
        const content = result.response?.body || '';
        if (this.hasStackTrace(content)) {
            vulnerabilities.push({
                id: `error-stack-${result.surface.name}-${Date.now()}`,
                title: 'Stack Trace Disclosure (Induced)',
                description: `Input '${result.surface.name}' triggers stack trace disclosure when provided with malformed data`,
                severity: enums_1.VulnerabilitySeverity.MEDIUM,
                category: enums_1.VulnerabilityCategory.INFORMATION_DISCLOSURE,
                cwe: 'CWE-209',
                owasp: 'A04:2021',
                evidence: {
                    request: { body: result.payload },
                    response: { body: content.substring(0, 1000) },
                },
                remediation: 'Implement generic error pages and disable detailed error messages in production. Configure production environment to show generic error pages, log detailed errors server-side.',
                references: [
                    'https://cwe.mitre.org/data/definitions/209.html',
                    'https://owasp.org/www-community/Improper_Error_Handling',
                ],
                timestamp: new Date(),
            });
        }
        if (this.hasDatabaseError(content)) {
            vulnerabilities.push({
                id: `error-db-${result.surface.name}-${Date.now()}`,
                title: 'Database Error Disclosure (Induced)',
                description: `Input '${result.surface.name}' triggers database error messages`,
                severity: enums_1.VulnerabilitySeverity.MEDIUM,
                category: enums_1.VulnerabilityCategory.INFORMATION_DISCLOSURE,
                cwe: 'CWE-209',
                owasp: 'A04:2021',
                evidence: {
                    request: { body: result.payload },
                    response: { body: content.substring(0, 1000) },
                },
                remediation: 'Implement generic error pages and disable detailed error messages in production. Remove or disable debug mode, implement custom error handlers.',
                references: [
                    'https://cwe.mitre.org/data/definitions/209.html',
                    'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
                ],
                timestamp: new Date(),
            });
        }
        return vulnerabilities;
    }
    async validate() {
        return true;
    }
    getPayloads() {
        return this.getErrorTriggeringPayloads();
    }
    createVulnerability(errorType, title, description, evidence, url) {
        const severityMap = {
            [ErrorType.STACK_TRACE]: enums_1.VulnerabilitySeverity.MEDIUM,
            [ErrorType.DATABASE_ERROR]: enums_1.VulnerabilitySeverity.MEDIUM,
            [ErrorType.PATH_DISCLOSURE]: enums_1.VulnerabilitySeverity.LOW,
            [ErrorType.DEBUG_INFO]: enums_1.VulnerabilitySeverity.LOW,
            [ErrorType.EXCEPTION]: enums_1.VulnerabilitySeverity.MEDIUM,
        };
        return {
            id: `error-${errorType}-${Date.now()}`,
            title,
            description,
            severity: severityMap[errorType],
            category: enums_1.VulnerabilityCategory.INFORMATION_DISCLOSURE,
            cwe: 'CWE-209',
            owasp: 'A04:2021',
            references: [
                'https://cwe.mitre.org/data/definitions/209.html',
                'https://owasp.org/www-community/Improper_Error_Handling',
                'https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html',
            ],
            url,
            evidence: {
                response: {
                    body: this.extractErrorSnippet(evidence, errorType),
                    snippet: evidence.substring(0, 500),
                },
            },
            remediation: 'Implement generic error pages and disable detailed error messages in production. Configure production environment to show generic error pages, log detailed errors server-side instead of displaying to users, remove or disable debug mode in production.',
            timestamp: new Date(),
        };
    }
    extractErrorSnippet(content, errorType) {
        const lines = content.split('\n');
        switch (errorType) {
            case ErrorType.STACK_TRACE:
                for (const line of lines) {
                    if (/at\s+[\w$.]+\s*\([^)]+:\d+:\d+\)/i.test(line)) {
                        return line.trim();
                    }
                }
                break;
            case ErrorType.DATABASE_ERROR:
                for (const line of lines) {
                    if (/sql|mysql|postgresql|oracle|database/i.test(line)) {
                        return line.trim();
                    }
                }
                break;
            case ErrorType.PATH_DISCLOSURE:
                for (const line of lines) {
                    if (/[A-Z]:\\[\w\\.-]+|\/home\/|\/var\/www\//i.test(line)) {
                        return line.trim();
                    }
                }
                break;
            case ErrorType.DEBUG_INFO:
                for (const line of lines) {
                    if (/debug|trace|var_dump|print_r/i.test(line)) {
                        return line.trim();
                    }
                }
                break;
        }
        return content.substring(0, 200);
    }
}
exports.ErrorBasedDetector = ErrorBasedDetector;
//# sourceMappingURL=ErrorBasedDetector.js.map