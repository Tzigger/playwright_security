"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.BaseScanner = void 0;
class BaseScanner {
    context;
    startTime;
    async initialize(context) {
        this.context = context;
        this.startTime = new Date();
        await this.onInitialize();
    }
    async cleanup() {
        await this.onCleanup();
        this.context = undefined;
    }
    isEnabled(config) {
        return this.type === 'passive'
            ? config.scanners.passive.enabled
            : config.scanners.active.enabled;
    }
    getDependencies() {
        return [];
    }
    validateConfig(_config) {
        return true;
    }
    async onInitialize() {
    }
    async onCleanup() {
    }
    getContext() {
        if (!this.context) {
            throw new Error(`Scanner ${this.id} not initialized`);
        }
        return this.context;
    }
}
exports.BaseScanner = BaseScanner;
//# sourceMappingURL=IScanner.js.map