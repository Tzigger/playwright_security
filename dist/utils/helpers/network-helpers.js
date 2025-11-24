"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.parseUrl = parseUrl;
exports.isUrlInScope = isUrlInScope;
exports.matchesPattern = matchesPattern;
exports.isSameOrigin = isSameOrigin;
exports.extractDomain = extractDomain;
exports.isExternalUrl = isExternalUrl;
exports.normalizeUrl = normalizeUrl;
exports.extractQueryParams = extractQueryParams;
exports.hasQueryParams = hasQueryParams;
exports.buildUrl = buildUrl;
exports.isJsonResponse = isJsonResponse;
exports.isHtmlResponse = isHtmlResponse;
exports.isStaticResource = isStaticResource;
function parseUrl(url) {
    try {
        return new URL(url);
    }
    catch {
        return null;
    }
}
function isUrlInScope(url, includePatterns, excludePatterns) {
    for (const pattern of excludePatterns) {
        if (matchesPattern(url, pattern)) {
            return false;
        }
    }
    if (includePatterns.length === 0) {
        return true;
    }
    for (const pattern of includePatterns) {
        if (matchesPattern(url, pattern)) {
            return true;
        }
    }
    return false;
}
function matchesPattern(url, pattern) {
    try {
        const regex = new RegExp(pattern);
        return regex.test(url);
    }
    catch {
        return url.includes(pattern);
    }
}
function isSameOrigin(url1, url2) {
    const parsed1 = parseUrl(url1);
    const parsed2 = parseUrl(url2);
    if (!parsed1 || !parsed2) {
        return false;
    }
    return parsed1.origin === parsed2.origin;
}
function extractDomain(url) {
    const parsed = parseUrl(url);
    return parsed ? parsed.hostname : null;
}
function isExternalUrl(url, baseUrl) {
    return !isSameOrigin(url, baseUrl);
}
function normalizeUrl(url) {
    const parsed = parseUrl(url);
    if (!parsed) {
        return url;
    }
    parsed.hash = '';
    let pathname = parsed.pathname;
    if (pathname.endsWith('/') && pathname.length > 1) {
        pathname = pathname.slice(0, -1);
    }
    parsed.pathname = pathname;
    return parsed.toString();
}
function extractQueryParams(url) {
    const parsed = parseUrl(url);
    if (!parsed) {
        return {};
    }
    const params = {};
    parsed.searchParams.forEach((value, key) => {
        params[key] = value;
    });
    return params;
}
function hasQueryParams(url) {
    const parsed = parseUrl(url);
    if (!parsed) {
        return false;
    }
    return parsed.search.length > 1;
}
function buildUrl(baseUrl, params) {
    const parsed = parseUrl(baseUrl);
    if (!parsed) {
        return baseUrl;
    }
    Object.entries(params).forEach(([key, value]) => {
        parsed.searchParams.set(key, value);
    });
    return parsed.toString();
}
function isJsonResponse(headers) {
    const contentType = headers['content-type'] || headers['Content-Type'] || '';
    return contentType.includes('application/json');
}
function isHtmlResponse(headers) {
    const contentType = headers['content-type'] || headers['Content-Type'] || '';
    return contentType.includes('text/html');
}
function isStaticResource(url) {
    const staticExtensions = [
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico',
        '.css', '.woff', '.woff2', '.ttf', '.eot',
        '.mp4', '.mp3', '.pdf', '.zip',
    ];
    const lowerUrl = url.toLowerCase();
    return staticExtensions.some(ext => lowerUrl.endsWith(ext));
}
//# sourceMappingURL=network-helpers.js.map