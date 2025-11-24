"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.HtmlReporter = void 0;
const tslib_1 = require("tslib");
const fs = tslib_1.__importStar(require("fs"));
const path = tslib_1.__importStar(require("path"));
const handlebars_1 = tslib_1.__importDefault(require("handlebars"));
const IReporter_1 = require("./base/IReporter");
const enums_1 = require("../types/enums");
class HtmlReporter extends IReporter_1.BaseReporter {
    template;
    getFormat() {
        return enums_1.ReportFormat.HTML;
    }
    async init(config, options) {
        await super.init(config, options);
        const tplPath = path.join(__dirname, 'templates', 'report.hbs');
        let source;
        try {
            source = await fs.promises.readFile(tplPath, 'utf-8');
        }
        catch (_) {
            source = `<!doctype html><html><head><meta charset="utf-8"/><title>DAST Report</title>
      <style>body{font-family:system-ui,Arial,sans-serif;padding:24px;color:#0f172a}
      .sev{padding:2px 6px;border-radius:4px;color:white;font-size:12px}
      .critical{background:#991b1b}.high{background:#dc2626}.medium{background:#d97706}
      .low{background:#2563eb}.info{background:#64748b}
      table{border-collapse:collapse;width:100%} td,th{border:1px solid #e2e8f0;padding:8px}
      th{background:#f1f5f9;text-align:left}</style></head>
      <body><h1>DAST Report</h1>
      <p><b>Target:</b> {{targetUrl}} | <b>Duration:</b> {{duration}}ms</p>
      <p><b>Total:</b> {{summary.total}} | C:{{summary.critical}} H:{{summary.high}} M:{{summary.medium}} L:{{summary.low}} I:{{summary.info}}</p>
      <h2>Findings</h2>
      <table><thead><tr><th>Severity</th><th>Title</th><th>Category</th><th>Confidence</th><th>URL</th></tr></thead>
      <tbody>{{#each vulnerabilities}}
        <tr>
          <td><span class="sev {{severity}}">{{severity}}</span></td>
          <td>{{title}}</td>
          <td>{{category}}</td>
          <td>{{confidence}}</td>
          <td>{{location.url}}</td>
        </tr>
      {{/each}}</tbody></table></body></html>`;
        }
        this.template = handlebars_1.default.compile(source);
    }
    async generate(result) {
        if (!this.template)
            return;
        const html = this.template(result);
        const dir = this.options.outputDir;
        const fileName = (this.options.fileNameTemplate || 'scan-{{scanId}}.html').replace(/\{\{scanId\}\}/g, result.scanId);
        const outPath = path.join(dir, fileName);
        await fs.promises.mkdir(path.dirname(outPath), { recursive: true });
        await fs.promises.writeFile(outPath, html, 'utf-8');
    }
}
exports.HtmlReporter = HtmlReporter;
//# sourceMappingURL=HtmlReporter.js.map