import { Page, Locator } from '@playwright/test';
export declare function findInputElements(page: Page): Promise<Locator[]>;
export declare function findForms(page: Page): Promise<Locator[]>;
export declare function findLinks(page: Page): Promise<Locator[]>;
export declare function isElementVisible(element: Locator): Promise<boolean>;
export declare function isElementEditable(element: Locator): Promise<boolean>;
export declare function getElementAttributes(element: Locator): Promise<Record<string, string>>;
export declare function getElementSelector(element: Locator): Promise<string>;
export declare function getElementPosition(element: Locator): Promise<{
    x: number;
    y: number;
    width: number;
    height: number;
} | null>;
export declare function waitForElementStable(element: Locator, timeout?: number): Promise<void>;
export declare function safeFill(element: Locator, value: string): Promise<boolean>;
export declare function safeClick(element: Locator): Promise<boolean>;
export declare function getPageHTML(page: Page): Promise<string>;
export declare function getPageText(page: Page): Promise<string>;
export declare function takeScreenshot(page: Page): Promise<string>;
export declare function hasErrorMessages(page: Page): Promise<boolean>;
export declare function getErrorMessages(page: Page): Promise<string[]>;
//# sourceMappingURL=dom-helpers.d.ts.map