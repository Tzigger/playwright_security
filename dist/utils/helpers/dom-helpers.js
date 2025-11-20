export async function findInputElements(page) {
    const selectors = [
        'input:not([type="hidden"]):not([type="submit"]):not([type="button"])',
        'textarea',
        'select',
        '[contenteditable="true"]',
    ];
    const elements = [];
    for (const selector of selectors) {
        const locators = await page.locator(selector).all();
        elements.push(...locators);
    }
    return elements;
}
export async function findForms(page) {
    return await page.locator('form').all();
}
export async function findLinks(page) {
    return await page.locator('a[href]').all();
}
export async function isElementVisible(element) {
    try {
        return await element.isVisible();
    }
    catch {
        return false;
    }
}
export async function isElementEditable(element) {
    try {
        return await element.isEditable();
    }
    catch {
        return false;
    }
}
export async function getElementAttributes(element) {
    try {
        const attributes = {};
        const attrNames = ['id', 'name', 'class', 'type', 'value', 'placeholder', 'required'];
        for (const attr of attrNames) {
            const value = await element.getAttribute(attr);
            if (value !== null) {
                attributes[attr] = value;
            }
        }
        return attributes;
    }
    catch {
        return {};
    }
}
export async function getElementSelector(element) {
    try {
        const id = await element.getAttribute('id');
        if (id) {
            return `#${id}`;
        }
        const name = await element.getAttribute('name');
        if (name) {
            return `[name="${name}"]`;
        }
        const tagName = await element.evaluate((el) => el.tagName.toLowerCase());
        return tagName;
    }
    catch {
        return 'unknown';
    }
}
export async function getElementPosition(element) {
    try {
        const box = await element.boundingBox();
        return box;
    }
    catch {
        return null;
    }
}
export async function waitForElementStable(element, timeout = 1000) {
    try {
        await element.waitFor({ state: 'attached', timeout });
    }
    catch {
    }
}
export async function safeFill(element, value) {
    try {
        await element.clear();
        await element.fill(value);
        return true;
    }
    catch {
        return false;
    }
}
export async function safeClick(element) {
    try {
        await element.click({ timeout: 5000 });
        return true;
    }
    catch {
        return false;
    }
}
export async function getPageHTML(page) {
    return await page.content();
}
export async function getPageText(page) {
    return await page.textContent('body') || '';
}
export async function takeScreenshot(page) {
    const screenshot = await page.screenshot();
    return screenshot.toString('base64');
}
export async function hasErrorMessages(page) {
    const errorSelectors = [
        '.error',
        '.alert-error',
        '.alert-danger',
        '[class*="error"]',
        '[role="alert"]',
    ];
    for (const selector of errorSelectors) {
        const count = await page.locator(selector).count();
        if (count > 0) {
            return true;
        }
    }
    return false;
}
export async function getErrorMessages(page) {
    const errorSelectors = [
        '.error',
        '.alert-error',
        '.alert-danger',
        '[class*="error"]',
        '[role="alert"]',
    ];
    const messages = [];
    for (const selector of errorSelectors) {
        const elements = await page.locator(selector).all();
        for (const element of elements) {
            const text = await element.textContent();
            if (text) {
                messages.push(text.trim());
            }
        }
    }
    return messages;
}
//# sourceMappingURL=dom-helpers.js.map