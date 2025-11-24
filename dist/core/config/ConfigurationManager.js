"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ConfigurationManager = void 0;
const tslib_1 = require("tslib");
const Logger_1 = require("../../utils/logger/Logger");
const enums_1 = require("../../types/enums");
const config_validator_1 = require("../../utils/validators/config-validator");
const fs = tslib_1.__importStar(require("fs"));
const path = tslib_1.__importStar(require("path"));
class ConfigurationManager {
    static instance;
    logger;
    currentConfig = null;
    constructor() {
        this.logger = new Logger_1.Logger(enums_1.LogLevel.INFO, 'ConfigurationManager');
    }
    static getInstance() {
        if (!ConfigurationManager.instance) {
            ConfigurationManager.instance = new ConfigurationManager();
        }
        return ConfigurationManager.instance;
    }
    async loadFromFile(filePath) {
        this.logger.info(`Loading configuration from: ${filePath}`);
        try {
            const absolutePath = path.resolve(filePath);
            if (!fs.existsSync(absolutePath)) {
                throw new Error(`Configuration file not found: ${absolutePath}`);
            }
            const fileContent = fs.readFileSync(absolutePath, 'utf-8');
            const config = JSON.parse(fileContent);
            const validation = (0, config_validator_1.validateScanConfiguration)(config);
            if (!validation.valid) {
                throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
            }
            this.currentConfig = config;
            this.logger.info('Configuration loaded and validated successfully');
            return config;
        }
        catch (error) {
            this.logger.error(`Failed to load configuration: ${error}`);
            throw error;
        }
    }
    loadFromObject(config) {
        this.logger.info('Loading configuration from object');
        try {
            const validation = (0, config_validator_1.validateScanConfiguration)(config);
            if (!validation.valid) {
                throw new Error(`Invalid configuration: ${validation.errors.join(', ')}`);
            }
            this.currentConfig = config;
            this.logger.info('Configuration loaded and validated successfully');
            return config;
        }
        catch (error) {
            this.logger.error(`Failed to load configuration: ${error}`);
            throw error;
        }
    }
    async loadDefault() {
        this.logger.info('Loading default configuration');
        const defaultConfigPath = path.join(__dirname, '../../../config/default.config.json');
        return this.loadFromFile(defaultConfigPath);
    }
    async loadProfile(profileName) {
        this.logger.info(`Loading profile: ${profileName}`);
        const profilePath = path.join(__dirname, `../../../config/profiles/${profileName}.json`);
        return this.loadFromFile(profilePath);
    }
    mergeConfig(overrides) {
        if (!this.currentConfig) {
            throw new Error('No configuration loaded. Load a configuration first.');
        }
        this.logger.info('Merging configuration with overrides');
        const merged = this.deepMerge(this.currentConfig, overrides);
        const validation = (0, config_validator_1.validateScanConfiguration)(merged);
        if (!validation.valid) {
            throw new Error(`Invalid merged configuration: ${validation.errors.join(', ')}`);
        }
        this.currentConfig = merged;
        return merged;
    }
    async saveToFile(filePath) {
        if (!this.currentConfig) {
            throw new Error('No configuration to save. Load a configuration first.');
        }
        this.logger.info(`Saving configuration to: ${filePath}`);
        try {
            const absolutePath = path.resolve(filePath);
            const dirPath = path.dirname(absolutePath);
            if (!fs.existsSync(dirPath)) {
                fs.mkdirSync(dirPath, { recursive: true });
            }
            const jsonContent = JSON.stringify(this.currentConfig, null, 2);
            fs.writeFileSync(absolutePath, jsonContent, 'utf-8');
            this.logger.info('Configuration saved successfully');
        }
        catch (error) {
            this.logger.error(`Failed to save configuration: ${error}`);
            throw error;
        }
    }
    getConfig() {
        if (!this.currentConfig) {
            throw new Error('No configuration loaded. Load a configuration first.');
        }
        return this.currentConfig;
    }
    hasConfig() {
        return this.currentConfig !== null;
    }
    reset() {
        this.logger.info('Resetting configuration');
        this.currentConfig = null;
    }
    listProfiles() {
        const profilesDir = path.join(__dirname, '../../../config/profiles');
        if (!fs.existsSync(profilesDir)) {
            return [];
        }
        const files = fs.readdirSync(profilesDir);
        return files
            .filter((file) => file.endsWith('.json'))
            .map((file) => file.replace('.json', ''));
    }
    deepMerge(target, source) {
        const result = { ...target };
        for (const key in source) {
            if (source.hasOwnProperty(key)) {
                if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
                    result[key] = this.deepMerge(target[key] || {}, source[key]);
                }
                else {
                    result[key] = source[key];
                }
            }
        }
        return result;
    }
    exportAsJson() {
        if (!this.currentConfig) {
            throw new Error('No configuration to export. Load a configuration first.');
        }
        return JSON.stringify(this.currentConfig, null, 2);
    }
    cloneConfig() {
        if (!this.currentConfig) {
            throw new Error('No configuration to clone. Load a configuration first.');
        }
        return JSON.parse(JSON.stringify(this.currentConfig));
    }
    setLogLevel(level) {
        this.logger.setLevel(level);
    }
}
exports.ConfigurationManager = ConfigurationManager;
//# sourceMappingURL=ConfigurationManager.js.map