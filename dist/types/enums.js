"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.VerbosityLevel = exports.SensitivityLevel = exports.AggressivenessLevel = exports.AuthType = exports.ReportFormat = exports.LogLevel = exports.BrowserType = exports.ScanStatus = exports.DetectorType = exports.ScannerType = exports.HttpMethod = exports.VulnerabilityCategory = exports.VulnerabilitySeverity = void 0;
var VulnerabilitySeverity;
(function (VulnerabilitySeverity) {
    VulnerabilitySeverity["CRITICAL"] = "critical";
    VulnerabilitySeverity["HIGH"] = "high";
    VulnerabilitySeverity["MEDIUM"] = "medium";
    VulnerabilitySeverity["LOW"] = "low";
    VulnerabilitySeverity["INFO"] = "info";
})(VulnerabilitySeverity || (exports.VulnerabilitySeverity = VulnerabilitySeverity = {}));
var VulnerabilityCategory;
(function (VulnerabilityCategory) {
    VulnerabilityCategory["INJECTION"] = "injection";
    VulnerabilityCategory["XSS"] = "xss";
    VulnerabilityCategory["DATA_EXPOSURE"] = "data-exposure";
    VulnerabilityCategory["INFORMATION_DISCLOSURE"] = "information-disclosure";
    VulnerabilityCategory["INSECURE_TRANSMISSION"] = "insecure-transmission";
    VulnerabilityCategory["INSECURE_COMMUNICATION"] = "insecure-communication";
    VulnerabilityCategory["AUTHENTICATION"] = "authentication";
    VulnerabilityCategory["BROKEN_AUTHENTICATION"] = "broken-authentication";
    VulnerabilityCategory["AUTHORIZATION"] = "authorization";
    VulnerabilityCategory["CONFIGURATION"] = "configuration";
    VulnerabilityCategory["SECURITY_MISCONFIGURATION"] = "security-misconfiguration";
    VulnerabilityCategory["CRYPTOGRAPHY"] = "cryptography";
    VulnerabilityCategory["CSRF"] = "csrf";
    VulnerabilityCategory["CLICKJACKING"] = "clickjacking";
    VulnerabilityCategory["SECURITY_HEADERS"] = "security-headers";
})(VulnerabilityCategory || (exports.VulnerabilityCategory = VulnerabilityCategory = {}));
var HttpMethod;
(function (HttpMethod) {
    HttpMethod["GET"] = "GET";
    HttpMethod["POST"] = "POST";
    HttpMethod["PUT"] = "PUT";
    HttpMethod["DELETE"] = "DELETE";
    HttpMethod["PATCH"] = "PATCH";
    HttpMethod["HEAD"] = "HEAD";
    HttpMethod["OPTIONS"] = "OPTIONS";
})(HttpMethod || (exports.HttpMethod = HttpMethod = {}));
var ScannerType;
(function (ScannerType) {
    ScannerType["PASSIVE"] = "passive";
    ScannerType["ACTIVE"] = "active";
    ScannerType["HYBRID"] = "hybrid";
})(ScannerType || (exports.ScannerType = ScannerType = {}));
var DetectorType;
(function (DetectorType) {
    DetectorType["PASSIVE"] = "passive";
    DetectorType["ACTIVE"] = "active";
})(DetectorType || (exports.DetectorType = DetectorType = {}));
var ScanStatus;
(function (ScanStatus) {
    ScanStatus["PENDING"] = "pending";
    ScanStatus["RUNNING"] = "running";
    ScanStatus["COMPLETED"] = "completed";
    ScanStatus["FAILED"] = "failed";
    ScanStatus["CANCELLED"] = "cancelled";
})(ScanStatus || (exports.ScanStatus = ScanStatus = {}));
var BrowserType;
(function (BrowserType) {
    BrowserType["CHROMIUM"] = "chromium";
    BrowserType["FIREFOX"] = "firefox";
    BrowserType["WEBKIT"] = "webkit";
})(BrowserType || (exports.BrowserType = BrowserType = {}));
var LogLevel;
(function (LogLevel) {
    LogLevel["ERROR"] = "error";
    LogLevel["WARN"] = "warn";
    LogLevel["INFO"] = "info";
    LogLevel["DEBUG"] = "debug";
})(LogLevel || (exports.LogLevel = LogLevel = {}));
var ReportFormat;
(function (ReportFormat) {
    ReportFormat["JSON"] = "json";
    ReportFormat["HTML"] = "html";
    ReportFormat["SARIF"] = "sarif";
    ReportFormat["CONSOLE"] = "console";
    ReportFormat["MARKDOWN"] = "markdown";
})(ReportFormat || (exports.ReportFormat = ReportFormat = {}));
var AuthType;
(function (AuthType) {
    AuthType["BASIC"] = "basic";
    AuthType["FORM"] = "form";
    AuthType["BEARER"] = "bearer";
    AuthType["CUSTOM"] = "custom";
    AuthType["NONE"] = "none";
})(AuthType || (exports.AuthType = AuthType = {}));
var AggressivenessLevel;
(function (AggressivenessLevel) {
    AggressivenessLevel["LOW"] = "low";
    AggressivenessLevel["MEDIUM"] = "medium";
    AggressivenessLevel["HIGH"] = "high";
})(AggressivenessLevel || (exports.AggressivenessLevel = AggressivenessLevel = {}));
var SensitivityLevel;
(function (SensitivityLevel) {
    SensitivityLevel["STRICT"] = "strict";
    SensitivityLevel["NORMAL"] = "normal";
    SensitivityLevel["RELAXED"] = "relaxed";
})(SensitivityLevel || (exports.SensitivityLevel = SensitivityLevel = {}));
var VerbosityLevel;
(function (VerbosityLevel) {
    VerbosityLevel["MINIMAL"] = "minimal";
    VerbosityLevel["NORMAL"] = "normal";
    VerbosityLevel["DETAILED"] = "detailed";
})(VerbosityLevel || (exports.VerbosityLevel = VerbosityLevel = {}));
//# sourceMappingURL=enums.js.map