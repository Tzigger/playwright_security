"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.SarifReporter = void 0;
const tslib_1 = require("tslib");
const fs = tslib_1.__importStar(require("fs"));
const path = tslib_1.__importStar(require("path"));
const IReporter_1 = require("./base/IReporter");
const enums_1 = require("../types/enums");
class SarifReporter extends IReporter_1.BaseReporter {
    getFormat() {
        return enums_1.ReportFormat.SARIF;
    }
    async generate(result) {
        const sarif = this.toSarif(result);
        const dir = this.options.outputDir;
        const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.sarif').replace(/\{\{scanId\}\}/g, result.scanId);
        const outPath = path.join(dir, fileName);
        await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
        await fs.promises.writeFile(outPath, JSON.stringify(sarif, null, 2), 'utf-8');
    }
    toSarif(result) {
        const toolName = 'playwright_security';
        const rulesMap = {};
        const results = result.vulnerabilities.map((v, idx) => {
            const ruleId = v.cwe || v.category || `VULN-${idx}`;
            if (!rulesMap[ruleId]) {
                rulesMap[ruleId] = {
                    id: ruleId,
                    name: v.title,
                    shortDescription: { text: v.title },
                    fullDescription: { text: v.description || v.title },
                    help: { text: v.remediation || '' },
                    properties: { category: v.category, severity: v.severity },
                };
            }
            return {
                ruleId,
                level: this.severityToSarif(v.severity),
                message: { text: v.title },
                locations: [
                    {
                        physicalLocation: {
                            artifactLocation: { uri: v.url || result.targetUrl },
                        },
                    },
                ],
            };
        });
        return {
            $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
            version: '2.1.0',
            runs: [
                {
                    tool: {
                        driver: {
                            name: toolName,
                            rules: Object.values(rulesMap),
                        },
                    },
                    results,
                },
            ],
        };
    }
    severityToSarif(sev) {
        if (sev === 'critical' || sev === 'high')
            return 'error';
        if (sev === 'medium')
            return 'warning';
        return 'note';
    }
}
exports.SarifReporter = SarifReporter;
//# sourceMappingURL=SarifReporter.js.map