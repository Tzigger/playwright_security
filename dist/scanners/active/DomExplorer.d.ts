import { LogLevel } from '../../types/enums';
import { Page } from 'playwright';
export declare enum AttackSurfaceType {
    FORM_INPUT = "form-input",
    URL_PARAMETER = "url-parameter",
    LINK = "link",
    BUTTON = "button",
    COOKIE = "cookie",
    HEADER = "header",
    JSON_BODY = "json-body"
}
export declare enum InjectionContext {
    HTML = "html",
    HTML_ATTRIBUTE = "html-attribute",
    JAVASCRIPT = "javascript",
    URL = "url",
    SQL = "sql",
    JSON = "json",
    XML = "xml"
}
export interface AttackSurface {
    id: string;
    type: AttackSurfaceType;
    element?: any;
    selector?: string;
    name: string;
    value?: string;
    context: InjectionContext;
    metadata: {
        formAction?: string;
        formMethod?: string;
        inputType?: string;
        url?: string;
        parameterName?: string;
        [key: string]: any;
    };
}
export interface FormInfo {
    action: string;
    method: string;
    inputs: AttackSurface[];
    submitButton?: any;
}
export declare class DomExplorer {
    private logger;
    constructor(logLevel?: LogLevel);
    explore(page: Page): Promise<AttackSurface[]>;
    discoverForms(page: Page): Promise<FormInfo[]>;
    private discoverFormInputs;
    private discoverUrlParameters;
    private discoverLinks;
    private discoverCookies;
    private determineContext;
    filterByType(surfaces: AttackSurface[], type: AttackSurfaceType): AttackSurface[];
    filterByContext(surfaces: AttackSurface[], context: InjectionContext): AttackSurface[];
    getSqlInjectionTargets(surfaces: AttackSurface[]): AttackSurface[];
    getXssTargets(surfaces: AttackSurface[]): AttackSurface[];
}
//# sourceMappingURL=DomExplorer.d.ts.map