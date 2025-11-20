export function validateScanConfiguration(config) {
    const errors = [];
    if (!config.target?.url) {
        errors.push('Target URL is required');
    }
    else if (!isValidUrl(config.target.url)) {
        errors.push('Target URL is invalid');
    }
    if (config.browser) {
        if (!['chromium', 'firefox', 'webkit'].includes(config.browser.type)) {
            errors.push('Invalid browser type');
        }
    }
    if (config.reporting) {
        if (!config.reporting.outputDir) {
            errors.push('Output directory is required');
        }
        if (config.reporting.formats.length === 0) {
            errors.push('At least one report format must be specified');
        }
    }
    if (config.advanced) {
        if (config.advanced.parallelism && config.advanced.parallelism < 1) {
            errors.push('Parallelism must be at least 1');
        }
        if (config.advanced.maxRetries && config.advanced.maxRetries < 0) {
            errors.push('Max retries cannot be negative');
        }
    }
    return {
        valid: errors.length === 0,
        errors,
    };
}
export function isValidUrl(url) {
    try {
        const parsed = new URL(url);
        return ['http:', 'https:'].includes(parsed.protocol);
    }
    catch {
        return false;
    }
}
export function isValidRegex(pattern) {
    try {
        new RegExp(pattern);
        return true;
    }
    catch {
        return false;
    }
}
export function isValidPath(path) {
    if (path.includes('\0'))
        return false;
    if (path.trim().length === 0)
        return false;
    return true;
}
export function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}
export function isValidPort(port) {
    return Number.isInteger(port) && port >= 1 && port <= 65535;
}
export function isValidConfidence(confidence) {
    return typeof confidence === 'number' && confidence >= 0 && confidence <= 1;
}
//# sourceMappingURL=config-validator.js.map