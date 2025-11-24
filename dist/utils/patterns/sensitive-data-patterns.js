"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SENSITIVE_DATA_PATTERN_MAP = exports.ALL_SENSITIVE_PATTERNS = exports.INTERNAL_IP_PATTERNS = exports.DB_CONNECTION_PATTERNS = exports.JWT_PATTERNS = exports.PRIVATE_KEY_PATTERNS = exports.SSN_PATTERNS = exports.CREDIT_CARD_PATTERNS = exports.PHONE_PATTERNS = exports.EMAIL_PATTERNS = exports.PASSWORD_PATTERNS = exports.API_KEY_PATTERNS = void 0;
exports.API_KEY_PATTERNS = [
    /api[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})/gi,
    /apikey['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_\-]{20,})/gi,
    /AKIA[0-9A-Z]{16}/g,
    /aws[_-]?access[_-]?key[_-]?id['"]?\s*[:=]\s*['"]?([a-zA-Z0-9]{20})/gi,
    /aws[_-]?secret[_-]?access[_-]?key['"]?\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})/gi,
    /AIza[0-9A-Za-z\-_]{35}/g,
    /gh[pousr]_[0-9a-zA-Z]{36}/g,
    /github[_-]?token['"]?\s*[:=]\s*['"]?([a-zA-Z0-9_]{40})/gi,
    /sk_live_[0-9a-zA-Z]{24}/g,
    /pk_live_[0-9a-zA-Z]{24}/g,
    /xox[baprs]-([0-9a-zA-Z]{10,48})/g,
    /SK[0-9a-fA-F]{32}/g,
];
exports.PASSWORD_PATTERNS = [
    /['"]password['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
    /['"]passwd['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
    /['"]pwd['"]\s*:\s*['"]([^'"]{6,})['"]/gi,
    /<password>([^<]+)<\/password>/gi,
];
exports.EMAIL_PATTERNS = [
    /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
];
exports.PHONE_PATTERNS = [
    /\+?[1-9]\d{1,14}/g,
    /\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
];
exports.CREDIT_CARD_PATTERNS = [
    /\b4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    /\b5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g,
    /\b3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}\b/g,
];
exports.SSN_PATTERNS = [
    /\b\d{3}-\d{2}-\d{4}\b/g,
    /\b[1-8]\d{12}\b/g,
];
exports.PRIVATE_KEY_PATTERNS = [
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g,
    /-----BEGIN PGP PRIVATE KEY BLOCK-----/g,
];
exports.JWT_PATTERNS = [
    /eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g,
];
exports.DB_CONNECTION_PATTERNS = [
    /mongodb(\+srv)?:\/\/[^'"<>\s]+/gi,
    /postgres(ql)?:\/\/[^'"<>\s]+/gi,
    /mysql:\/\/[^'"<>\s]+/gi,
    /redis:\/\/[^'"<>\s]+/gi,
];
exports.INTERNAL_IP_PATTERNS = [
    /\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
    /\b172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b/g,
    /\b192\.168\.\d{1,3}\.\d{1,3}\b/g,
    /\b127\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g,
];
exports.ALL_SENSITIVE_PATTERNS = [
    ...exports.API_KEY_PATTERNS,
    ...exports.PASSWORD_PATTERNS,
    ...exports.EMAIL_PATTERNS,
    ...exports.CREDIT_CARD_PATTERNS,
    ...exports.SSN_PATTERNS,
    ...exports.PRIVATE_KEY_PATTERNS,
    ...exports.JWT_PATTERNS,
    ...exports.DB_CONNECTION_PATTERNS,
    ...exports.INTERNAL_IP_PATTERNS,
];
exports.SENSITIVE_DATA_PATTERN_MAP = [
    {
        patterns: exports.API_KEY_PATTERNS,
        category: 'API Keys',
        severity: 'critical',
        description: 'API keys exposed in response',
    },
    {
        patterns: exports.PASSWORD_PATTERNS,
        category: 'Passwords',
        severity: 'critical',
        description: 'Plain-text passwords in response',
    },
    {
        patterns: exports.PRIVATE_KEY_PATTERNS,
        category: 'Private Keys',
        severity: 'critical',
        description: 'Private cryptographic keys exposed',
    },
    {
        patterns: exports.DB_CONNECTION_PATTERNS,
        category: 'Database Credentials',
        severity: 'critical',
        description: 'Database connection strings with credentials',
    },
    {
        patterns: exports.JWT_PATTERNS,
        category: 'JWT Tokens',
        severity: 'high',
        description: 'JWT tokens exposed in response',
    },
    {
        patterns: exports.CREDIT_CARD_PATTERNS,
        category: 'Credit Cards',
        severity: 'high',
        description: 'Credit card numbers exposed',
    },
    {
        patterns: exports.SSN_PATTERNS,
        category: 'Personal Identifiers',
        severity: 'high',
        description: 'SSN/CNP exposed in response',
    },
    {
        patterns: exports.EMAIL_PATTERNS,
        category: 'Email Addresses',
        severity: 'medium',
        description: 'Email addresses exposed',
    },
    {
        patterns: exports.PHONE_PATTERNS,
        category: 'Phone Numbers',
        severity: 'medium',
        description: 'Phone numbers exposed',
    },
    {
        patterns: exports.INTERNAL_IP_PATTERNS,
        category: 'Internal IPs',
        severity: 'low',
        description: 'Internal IP addresses exposed',
    },
];
//# sourceMappingURL=sensitive-data-patterns.js.map