import fs from 'fs/promises';
import path from 'path';

interface ManualFinding {
  page: string;
  vulnerability: string;
  input: string;
  payload: string;
  response: { status: number; bodySnippet: string; evidence?: string };
  cwe?: string;
}

interface AutomatedFinding {
  page: string;
  title: string;
  cwe?: string;
  confidence?: number;
}

interface MetricsSummary {
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  totalManual: number;
  totalAutomated: number;
  truePositiveRate: number;
  falsePositiveRate: number;
  precision: number;
  recall: number;
  f1Score: number;
  details: {
    truePositivePages: string[];
    falseNegativePages: string[];
    falsePositivePages: string[];
  };
}

async function loadManual(): Promise<ManualFinding[]> {
  const file = path.resolve(__dirname, '../manual/manual-findings.json');
  const raw = await fs.readFile(file, 'utf-8').catch(() => '[]');
  return JSON.parse(raw) as ManualFinding[];
}

async function loadAutomated(): Promise<AutomatedFinding[]> {
  const dir = path.resolve(__dirname, 'scan-logs');
  let files: string[] = [];
  try {
    files = await fs.readdir(dir);
  } catch {
    return [];
  }
  const findings: AutomatedFinding[] = [];
  for (const file of files) {
    const content = await fs.readFile(path.join(dir, file), 'utf-8');
    const pageMatch = file.replace(/\.log$/, '').replace(/^-+|-+$/g, '');
    const vulnLines = content.split(/\n/).filter((l) => l.startsWith('VULN '));
    vulnLines.forEach((line) => {
      const parts = line.replace('VULN ', '').split(' ');
      findings.push({ page: `/${pageMatch.replace(/-+/g, '_')}.php`, title: parts[0], cwe: parts.find((p) => p.startsWith('CWE='))?.replace('CWE=', '') });
    });
  }
  return findings;
}

function calculateMetrics(manual: ManualFinding[], auto: AutomatedFinding[]): MetricsSummary {
  const manualPages = new Set(manual.map(m => m.page));
  const autoPages = new Set(auto.map(a => a.page));
  
  const truePositivePages: string[] = [];
  const falseNegativePages: string[] = [];
  const falsePositivePages: string[] = [];
  
  // True Positives: pages in both manual and auto
  manualPages.forEach(page => {
    if (autoPages.has(page)) {
      truePositivePages.push(page);
    } else {
      falseNegativePages.push(page);
    }
  });
  
  // False Positives: pages in auto but not in manual
  autoPages.forEach(page => {
    if (!manualPages.has(page)) {
      falsePositivePages.push(page);
    }
  });
  
  const truePositives = truePositivePages.length;
  const falseNegatives = falseNegativePages.length;
  const falsePositives = falsePositivePages.length;
  const totalManual = manual.length;
  const totalAutomated = auto.length;
  
  // TPR = TP / (TP + FN) - proportion of actual positives correctly identified
  const truePositiveRate = totalManual > 0 ? truePositives / (truePositives + falseNegatives) : 0;
  
  // FPR = FP / (FP + TN) - for simplicity, we use FP / total automated findings
  const falsePositiveRate = totalAutomated > 0 ? falsePositives / totalAutomated : 0;
  
  // Precision = TP / (TP + FP)
  const precision = (truePositives + falsePositives) > 0 ? truePositives / (truePositives + falsePositives) : 0;
  
  // Recall = TP / (TP + FN) = TPR
  const recall = truePositiveRate;
  
  // F1 Score = 2 * (precision * recall) / (precision + recall)
  const f1Score = (precision + recall) > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
  
  return {
    truePositives,
    falseNegatives,
    falsePositives,
    totalManual,
    totalAutomated,
    truePositiveRate: Math.round(truePositiveRate * 1000) / 1000,
    falsePositiveRate: Math.round(falsePositiveRate * 1000) / 1000,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1Score: Math.round(f1Score * 1000) / 1000,
    details: {
      truePositivePages,
      falseNegativePages,
      falsePositivePages,
    },
  };
}

function renderRow(title: string, manual?: ManualFinding, auto?: AutomatedFinding): string {
  const status = manual && auto ? 'True Positive' : manual && !auto ? 'False Negative' : !manual && auto ? 'False Positive' : 'N/A';
  const statusClass = status === 'True Positive' ? 'tp' : status === 'False Negative' ? 'fn' : status === 'False Positive' ? 'fp' : '';
  return `
  <tr class="${statusClass}">
    <td>${title}</td>
    <td>${manual ? manual.page : '-'}</td>
    <td>${manual ? manual.vulnerability : '-'}</td>
    <td>${manual ? manual.payload : '-'}</td>
    <td>${auto ? auto.page : '-'}</td>
    <td>${auto ? auto.title : '-'}</td>
    <td>${status}</td>
  </tr>`;
}

async function buildReport(): Promise<void> {
  const manual = await loadManual();
  const auto = await loadAutomated();
  const metrics = calculateMetrics(manual, auto);

  const rows: string[] = [];
  const manualByPage = new Map(manual.map((m) => [m.page, m]));
  const autoByPage = new Map(auto.map((a) => [a.page, a]));
  const pages = new Set([...manualByPage.keys(), ...autoByPage.keys()]);

  pages.forEach((p) => {
    rows.push(renderRow(p, manualByPage.get(p), autoByPage.get(p)));
  });

  const html = `<!doctype html>
  <html><head><meta charset="utf-8"><title>Comparison Report</title>
  <style>
    table{border-collapse:collapse;width:100%;}
    td,th{border:1px solid #ccc;padding:6px;}
    th{background:#f5f5f5;}
    .tp{background:#d4edda;}
    .fn{background:#f8d7da;}
    .fp{background:#fff3cd;}
    .metrics{margin:20px 0;padding:15px;background:#e9ecef;border-radius:5px;}
    .metrics h3{margin-top:0;}
    .metric-value{font-weight:bold;font-size:1.2em;}
    .good{color:#28a745;}
    .bad{color:#dc3545;}
    .warn{color:#ffc107;}
  </style>
  </head><body>
  <h1>Manual vs Automated Comparison</h1>
  
  <div class="metrics">
    <h3>Detection Metrics</h3>
    <p>True Positives: <span class="metric-value good">${metrics.truePositives}</span></p>
    <p>False Negatives: <span class="metric-value ${metrics.falseNegatives > 0 ? 'bad' : 'good'}">${metrics.falseNegatives}</span></p>
    <p>False Positives: <span class="metric-value ${metrics.falsePositives > 0 ? 'warn' : 'good'}">${metrics.falsePositives}</span></p>
    <hr/>
    <p>True Positive Rate (Recall): <span class="metric-value ${metrics.truePositiveRate >= 0.9 ? 'good' : 'bad'}">${(metrics.truePositiveRate * 100).toFixed(1)}%</span> (Target: ≥90%)</p>
    <p>False Positive Rate: <span class="metric-value ${metrics.falsePositiveRate < 0.1 ? 'good' : 'bad'}">${(metrics.falsePositiveRate * 100).toFixed(1)}%</span> (Target: <10%)</p>
    <p>Precision: <span class="metric-value">${(metrics.precision * 100).toFixed(1)}%</span></p>
    <p>F1 Score: <span class="metric-value">${(metrics.f1Score * 100).toFixed(1)}%</span></p>
  </div>

  <table>
    <thead><tr><th>Page</th><th>Manual Page</th><th>Manual Vuln</th><th>Payload</th><th>Automated Page</th><th>Automated Vuln</th><th>Status</th></tr></thead>
    <tbody>${rows.join('')}</tbody>
  </table>
  </body></html>`;

  const outPath = path.resolve(__dirname, 'comparison-report.html');
  await fs.writeFile(outPath, html, 'utf-8');
  
  // Write metrics summary as JSON
  const metricsPath = path.resolve(__dirname, 'metrics-summary.json');
  await fs.writeFile(metricsPath, JSON.stringify(metrics, null, 2), 'utf-8');
  
  console.log(`Comparison report written to: ${outPath}`);
  console.log(`Metrics summary written to: ${metricsPath}`);
  console.log('\nMetrics Summary:');
  console.log(`  True Positive Rate: ${(metrics.truePositiveRate * 100).toFixed(1)}%`);
  console.log(`  False Positive Rate: ${(metrics.falsePositiveRate * 100).toFixed(1)}%`);
  console.log(`  Precision: ${(metrics.precision * 100).toFixed(1)}%`);
  console.log(`  F1 Score: ${(metrics.f1Score * 100).toFixed(1)}%`);
}

buildReport().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exit(1);
});
