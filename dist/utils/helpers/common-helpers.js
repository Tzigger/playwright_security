"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateUUID = generateUUID;
exports.generateShortId = generateShortId;
exports.hashString = hashString;
exports.encodeBase64 = encodeBase64;
exports.decodeBase64 = decodeBase64;
exports.sanitizeFilename = sanitizeFilename;
exports.truncate = truncate;
exports.deepClone = deepClone;
exports.sleep = sleep;
exports.retry = retry;
exports.formatBytes = formatBytes;
exports.isEmpty = isEmpty;
function generateUUID() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
        const r = (Math.random() * 16) | 0;
        const v = c === 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
function generateShortId() {
    return Math.random().toString(36).substring(2, 11);
}
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        const char = str.charCodeAt(i);
        hash = (hash << 5) - hash + char;
        hash = hash & hash;
    }
    return Math.abs(hash).toString(36);
}
function encodeBase64(str) {
    return Buffer.from(str).toString('base64');
}
function decodeBase64(str) {
    return Buffer.from(str, 'base64').toString('utf-8');
}
function sanitizeFilename(filename) {
    return filename.replace(/[^a-z0-9]/gi, '_').toLowerCase();
}
function truncate(str, maxLength) {
    if (str.length <= maxLength) {
        return str;
    }
    return str.substring(0, maxLength - 3) + '...';
}
function deepClone(obj) {
    return JSON.parse(JSON.stringify(obj));
}
function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}
async function retry(fn, maxRetries = 3, delayMs = 1000) {
    let lastError;
    for (let i = 0; i < maxRetries; i++) {
        try {
            return await fn();
        }
        catch (error) {
            lastError = error;
            if (i < maxRetries - 1) {
                await sleep(delayMs * Math.pow(2, i));
            }
        }
    }
    throw lastError;
}
function formatBytes(bytes) {
    if (bytes === 0)
        return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}
function isEmpty(obj) {
    if (obj === null || obj === undefined)
        return true;
    if (typeof obj === 'string')
        return obj.length === 0;
    if (Array.isArray(obj))
        return obj.length === 0;
    if (typeof obj === 'object')
        return Object.keys(obj).length === 0;
    return false;
}
//# sourceMappingURL=common-helpers.js.map