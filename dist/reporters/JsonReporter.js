"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.JsonReporter = void 0;
const tslib_1 = require("tslib");
const fs = tslib_1.__importStar(require("fs"));
const path = tslib_1.__importStar(require("path"));
const IReporter_1 = require("./base/IReporter");
const enums_1 = require("../types/enums");
class JsonReporter extends IReporter_1.BaseReporter {
    getFormat() {
        return enums_1.ReportFormat.JSON;
    }
    async generate(result) {
        const dir = this.options.outputDir;
        const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.json').replace(/\{\{scanId\}\}/g, result.scanId);
        const outPath = path.join(dir, fileName);
        await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
        await fs.promises.writeFile(outPath, JSON.stringify(result, null, 2), 'utf-8');
    }
}
exports.JsonReporter = JsonReporter;
//# sourceMappingURL=JsonReporter.js.map