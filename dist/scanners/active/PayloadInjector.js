"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.PayloadInjector = exports.PayloadEncoding = exports.InjectionStrategy = void 0;
const Logger_1 = require("../../utils/logger/Logger");
const enums_1 = require("../../types/enums");
const DomExplorer_1 = require("./DomExplorer");
var InjectionStrategy;
(function (InjectionStrategy) {
    InjectionStrategy["APPEND"] = "append";
    InjectionStrategy["REPLACE"] = "replace";
    InjectionStrategy["PREFIX"] = "prefix";
    InjectionStrategy["WRAP"] = "wrap";
})(InjectionStrategy || (exports.InjectionStrategy = InjectionStrategy = {}));
var PayloadEncoding;
(function (PayloadEncoding) {
    PayloadEncoding["NONE"] = "none";
    PayloadEncoding["URL"] = "url";
    PayloadEncoding["HTML"] = "html";
    PayloadEncoding["UNICODE"] = "unicode";
    PayloadEncoding["BASE64"] = "base64";
    PayloadEncoding["DOUBLE_URL"] = "double-url";
})(PayloadEncoding || (exports.PayloadEncoding = PayloadEncoding = {}));
class PayloadInjector {
    logger;
    constructor(logLevel = enums_1.LogLevel.INFO) {
        this.logger = new Logger_1.Logger(logLevel, 'PayloadInjector');
    }
    async inject(page, surface, payload, options = {}) {
        const encoding = options.encoding || PayloadEncoding.NONE;
        const strategy = options.strategy || InjectionStrategy.REPLACE;
        const submit = options.submit !== undefined ? options.submit : true;
        this.logger.debug(`Injecting payload into ${surface.name} (${surface.type})`);
        const result = {
            payload,
            encoding,
            strategy,
            surface,
        };
        try {
            const encodedPayload = this.encodePayload(payload, encoding);
            const finalPayload = this.applyStrategy(surface.value || '', encodedPayload, strategy);
            const startTime = Date.now();
            switch (surface.type) {
                case DomExplorer_1.AttackSurfaceType.FORM_INPUT:
                    await this.injectIntoFormInput(page, surface, finalPayload, submit);
                    break;
                case DomExplorer_1.AttackSurfaceType.URL_PARAMETER:
                    await this.injectIntoUrlParameter(page, surface, finalPayload);
                    break;
                case DomExplorer_1.AttackSurfaceType.COOKIE:
                    await this.injectIntoCookie(page, surface, finalPayload);
                    break;
                default:
                    throw new Error(`Unsupported attack surface type: ${surface.type}`);
            }
            await page.waitForLoadState('networkidle', { timeout: 5000 }).catch(() => { });
            const endTime = Date.now();
            result.response = {
                url: page.url(),
                status: 200,
                body: await page.content(),
                headers: {},
                timing: endTime - startTime,
            };
        }
        catch (error) {
            result.error = String(error);
            this.logger.debug(`Injection skipped (element unavailable): ${error}`);
        }
        return result;
    }
    async injectMultiple(page, surface, payloads, options = {}) {
        const results = [];
        const delayMs = options.delayMs || 100;
        for (let i = 0; i < payloads.length; i++) {
            const payload = payloads[i];
            if (!payload)
                continue;
            const encoding = options.encodings?.[i] || options.encoding || PayloadEncoding.NONE;
            const result = await this.inject(page, surface, payload, {
                ...options,
                encoding,
            });
            results.push(result);
            if (i < payloads.length - 1 && delayMs > 0) {
                await this.delay(delayMs);
            }
        }
        return results;
    }
    encodePayload(payload, encoding) {
        switch (encoding) {
            case PayloadEncoding.URL:
                return encodeURIComponent(payload);
            case PayloadEncoding.DOUBLE_URL:
                return encodeURIComponent(encodeURIComponent(payload));
            case PayloadEncoding.HTML:
                return payload
                    .replace(/&/g, '&amp;')
                    .replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;')
                    .replace(/"/g, '&quot;')
                    .replace(/'/g, '&#x27;');
            case PayloadEncoding.UNICODE:
                return this.unicodeEncode(payload);
            case PayloadEncoding.BASE64:
                return Buffer.from(payload).toString('base64');
            case PayloadEncoding.NONE:
            default:
                return payload;
        }
    }
    unicodeEncode(payload) {
        return payload
            .split('')
            .map((char) => {
            const rand = Math.random();
            if (rand < 0.7) {
                return char;
            }
            else if (rand < 0.85) {
                return `\\x${char.charCodeAt(0).toString(16).padStart(2, '0')}`;
            }
            else {
                return `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`;
            }
        })
            .join('');
    }
    applyStrategy(original, payload, strategy) {
        switch (strategy) {
            case InjectionStrategy.APPEND:
                return original + payload;
            case InjectionStrategy.PREFIX:
                return payload + original;
            case InjectionStrategy.WRAP:
                return payload + original + payload;
            case InjectionStrategy.REPLACE:
            default:
                return payload;
        }
    }
    async injectIntoFormInput(page, surface, payload, submit) {
        if (surface.selector) {
            await page.fill(surface.selector, payload, { timeout: 1000 });
        }
        else if (surface.element) {
            await surface.element.fill(payload, { timeout: 1000 });
        }
        else {
            throw new Error('No element or selector available for injection');
        }
        if (submit && surface.metadata?.formAction) {
            const submitBtn = await page.$('button[type="submit"], input[type="submit"]');
            if (submitBtn) {
                await submitBtn.click({ timeout: 1000 }).catch(() => { });
            }
        }
    }
    async injectIntoUrlParameter(page, surface, payload) {
        const currentUrl = new URL(page.url());
        currentUrl.searchParams.set(surface.name, payload);
        await page.goto(currentUrl.toString(), { waitUntil: 'domcontentloaded' });
    }
    async injectIntoCookie(page, surface, payload) {
        await page.context().addCookies([
            {
                name: surface.name,
                value: payload,
                domain: surface.metadata['domain'],
                path: surface.metadata['path'] || '/',
                secure: surface.metadata['secure'] || false,
                httpOnly: surface.metadata['httpOnly'] || false,
                sameSite: surface.metadata['sameSite'] || 'Lax',
            },
        ]);
        await page.reload({ waitUntil: 'domcontentloaded' });
    }
    generateFuzzingPayloads(context, count = 10) {
        const payloads = [];
        switch (context) {
            case DomExplorer_1.InjectionContext.SQL:
                payloads.push(...this.getSqlFuzzPayloads().slice(0, count));
                break;
            case DomExplorer_1.InjectionContext.HTML:
            case DomExplorer_1.InjectionContext.JAVASCRIPT:
                payloads.push(...this.getXssFuzzPayloads().slice(0, count));
                break;
            case DomExplorer_1.InjectionContext.URL:
                payloads.push(...this.getUrlFuzzPayloads().slice(0, count));
                break;
            default:
                payloads.push(...this.getGenericFuzzPayloads().slice(0, count));
        }
        return payloads;
    }
    getSqlFuzzPayloads() {
        return [
            "'", '"', '`',
            "' OR '1'='1", "' OR 1=1--", "' OR 'a'='a",
            "admin'--", "admin' #", "admin'/*",
            "' UNION SELECT NULL--",
            "' AND SLEEP(5)--",
            "1' AND '1'='2",
        ];
    }
    getXssFuzzPayloads() {
        return [
            '<script>alert(1)</script>',
            '<img src=x onerror=alert(1)>',
            '<svg/onload=alert(1)>',
            'javascript:alert(1)',
            '<iframe src="javascript:alert(1)">',
            '"><script>alert(1)</script>',
            "'-alert(1)-'",
            '<body onload=alert(1)>',
        ];
    }
    getUrlFuzzPayloads() {
        return [
            '../../../etc/passwd',
            '....//....//....//etc/passwd',
            '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
            'file:///etc/passwd',
            'http://evil.com',
        ];
    }
    getGenericFuzzPayloads() {
        return [
            'A'.repeat(1000),
            '%00',
            '${7*7}',
            '{{7*7}}',
            '\x00\x01\x02',
            '../../../',
            '<>"\';',
        ];
    }
    delay(ms) {
        return new Promise((resolve) => setTimeout(resolve, ms));
    }
}
exports.PayloadInjector = PayloadInjector;
//# sourceMappingURL=PayloadInjector.js.map