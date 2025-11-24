"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.DomExplorer = exports.InjectionContext = exports.AttackSurfaceType = void 0;
const Logger_1 = require("../../utils/logger/Logger");
const enums_1 = require("../../types/enums");
var AttackSurfaceType;
(function (AttackSurfaceType) {
    AttackSurfaceType["FORM_INPUT"] = "form-input";
    AttackSurfaceType["URL_PARAMETER"] = "url-parameter";
    AttackSurfaceType["LINK"] = "link";
    AttackSurfaceType["BUTTON"] = "button";
    AttackSurfaceType["COOKIE"] = "cookie";
    AttackSurfaceType["HEADER"] = "header";
    AttackSurfaceType["JSON_BODY"] = "json-body";
})(AttackSurfaceType || (exports.AttackSurfaceType = AttackSurfaceType = {}));
var InjectionContext;
(function (InjectionContext) {
    InjectionContext["HTML"] = "html";
    InjectionContext["HTML_ATTRIBUTE"] = "html-attribute";
    InjectionContext["JAVASCRIPT"] = "javascript";
    InjectionContext["URL"] = "url";
    InjectionContext["SQL"] = "sql";
    InjectionContext["JSON"] = "json";
    InjectionContext["XML"] = "xml";
})(InjectionContext || (exports.InjectionContext = InjectionContext = {}));
class DomExplorer {
    logger;
    constructor(logLevel = enums_1.LogLevel.INFO) {
        this.logger = new Logger_1.Logger(logLevel, 'DomExplorer');
    }
    async explore(page) {
        this.logger.info('Starting DOM exploration');
        const surfaces = [];
        try {
            const formSurfaces = await this.discoverFormInputs(page);
            surfaces.push(...formSurfaces);
            const urlSurfaces = await this.discoverUrlParameters(page);
            surfaces.push(...urlSurfaces);
            const linkSurfaces = await this.discoverLinks(page);
            surfaces.push(...linkSurfaces);
            const cookieSurfaces = await this.discoverCookies(page);
            surfaces.push(...cookieSurfaces);
            this.logger.info(`DOM exploration completed. Found ${surfaces.length} attack surfaces`);
        }
        catch (error) {
            this.logger.error(`Error during DOM exploration: ${error}`);
        }
        return surfaces;
    }
    async discoverForms(page) {
        const forms = [];
        try {
            const formElements = await page.$$('form');
            for (const form of formElements) {
                const action = (await form.getAttribute('action')) || page.url();
                const method = ((await form.getAttribute('method')) || 'GET').toUpperCase();
                const inputs = [];
                const inputElements = await form.$$('input, textarea, select');
                for (let i = 0; i < inputElements.length; i++) {
                    const input = inputElements[i];
                    if (!input)
                        continue;
                    const name = await input.getAttribute('name');
                    const type = await input.getAttribute('type') || 'text';
                    const value = await input.getAttribute('value') || '';
                    if (name && type !== 'submit' && type !== 'button') {
                        inputs.push({
                            id: `form-input-${i}`,
                            type: AttackSurfaceType.FORM_INPUT,
                            element: input,
                            selector: `input[name="${name}"]`,
                            name,
                            value,
                            context: this.determineContext(type, name),
                            metadata: {
                                formAction: action,
                                formMethod: method,
                                inputType: type,
                            },
                        });
                    }
                }
                const submitButton = await form.$('button[type="submit"], input[type="submit"]');
                forms.push({
                    action,
                    method,
                    inputs,
                    submitButton,
                });
            }
            this.logger.debug(`Discovered ${forms.length} forms`);
        }
        catch (error) {
            this.logger.error(`Error discovering forms: ${error}`);
        }
        return forms;
    }
    async discoverFormInputs(page) {
        const surfaces = [];
        const forms = await this.discoverForms(page);
        forms.forEach(form => {
            surfaces.push(...form.inputs);
        });
        return surfaces;
    }
    async discoverUrlParameters(page) {
        const surfaces = [];
        try {
            const url = new URL(page.url());
            const params = url.searchParams;
            let index = 0;
            params.forEach((value, key) => {
                surfaces.push({
                    id: `url-param-${index++}`,
                    type: AttackSurfaceType.URL_PARAMETER,
                    name: key,
                    value,
                    context: InjectionContext.URL,
                    metadata: {
                        url: page.url(),
                        parameterName: key,
                    },
                });
            });
            this.logger.debug(`Discovered ${surfaces.length} URL parameters`);
        }
        catch (error) {
            this.logger.debug(`Error discovering URL parameters: ${error}`);
        }
        return surfaces;
    }
    async discoverLinks(page) {
        const surfaces = [];
        try {
            const links = await page.$$eval('a[href]', (elements) => elements.map((el) => ({
                href: el.href,
                text: el.textContent?.trim() || '',
            })));
            const currentDomain = new URL(page.url()).hostname;
            links.forEach((link, index) => {
                try {
                    const linkUrl = new URL(link.href);
                    if (linkUrl.hostname === currentDomain) {
                        surfaces.push({
                            id: `link-${index}`,
                            type: AttackSurfaceType.LINK,
                            name: link.text || link.href,
                            value: link.href,
                            context: InjectionContext.URL,
                            metadata: {
                                url: link.href,
                                text: link.text,
                            },
                        });
                    }
                }
                catch (e) {
                }
            });
            this.logger.debug(`Discovered ${surfaces.length} links`);
        }
        catch (error) {
            this.logger.error(`Error discovering links: ${error}`);
        }
        return surfaces;
    }
    async discoverCookies(page) {
        const surfaces = [];
        try {
            const cookies = await page.context().cookies();
            cookies.forEach((cookie, index) => {
                surfaces.push({
                    id: `cookie-${index}`,
                    type: AttackSurfaceType.COOKIE,
                    name: cookie.name,
                    value: cookie.value,
                    context: InjectionContext.URL,
                    metadata: {
                        domain: cookie.domain,
                        path: cookie.path,
                        secure: cookie.secure,
                        httpOnly: cookie.httpOnly,
                        sameSite: cookie.sameSite,
                    },
                });
            });
            this.logger.debug(`Discovered ${cookies.length} cookies`);
        }
        catch (error) {
            this.logger.error(`Error discovering cookies: ${error}`);
        }
        return surfaces;
    }
    determineContext(inputType, name) {
        const lowerName = name.toLowerCase();
        if (lowerName.includes('search') ||
            lowerName.includes('query') ||
            lowerName.includes('id') ||
            lowerName.includes('user')) {
            return InjectionContext.SQL;
        }
        if (lowerName.includes('callback') || lowerName.includes('script')) {
            return InjectionContext.JAVASCRIPT;
        }
        if (inputType === 'url' || lowerName.includes('url') || lowerName.includes('link')) {
            return InjectionContext.URL;
        }
        return InjectionContext.HTML;
    }
    filterByType(surfaces, type) {
        return surfaces.filter((s) => s.type === type);
    }
    filterByContext(surfaces, context) {
        return surfaces.filter((s) => s.context === context);
    }
    getSqlInjectionTargets(surfaces) {
        return surfaces.filter((s) => s.context === InjectionContext.SQL ||
            s.name.toLowerCase().includes('search') ||
            s.name.toLowerCase().includes('id') ||
            s.name.toLowerCase().includes('query'));
    }
    getXssTargets(surfaces) {
        return surfaces.filter((s) => s.context === InjectionContext.HTML ||
            s.context === InjectionContext.JAVASCRIPT ||
            s.type === AttackSurfaceType.FORM_INPUT ||
            s.type === AttackSurfaceType.URL_PARAMETER);
    }
}
exports.DomExplorer = DomExplorer;
//# sourceMappingURL=DomExplorer.js.map