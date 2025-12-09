# bWAPP Validation Guide

This guide documents the bWAPP validation suite built with Kinetic.

## Authentication

Global setup performs bWAPP login (`bee`/`bug`, security level `0`) and saves state to `storage-states/bwapp-auth.json` for all tests and examples.

### Login Example

```typescript
// Example Playwright login sequence for bWAPP
await page.getByRole('textbox', { name: 'Login:' }).fill('bee');
await page.getByRole('textbox', { name: 'Password:' }).fill('bug');
await page.getByRole('button', { name: 'Login' }).click();
await page.locator('#select_portal').selectOption('0'); // Security level 0 (low)
await page.locator('button[name="form"]').click();
```

## Automated Validation (Playwright tests)
- Page-level scan: `tests/integration/bwapp-validation.spec.ts`
- Usage: `BWAPP_URL=http://localhost:8080 npx playwright test tests/integration/bwapp-validation.spec.ts`
- Element-level scan: `tests/integration/bwapp-element-scanner.spec.ts`
- Usage (ElementScanner): `BWAPP_URL=http://localhost:8080 npx playwright test tests/integration/bwapp-element-scanner.spec.ts`
- Coverage: SQLi, XSS (reflected/stored), command injection, path traversal, IDOR/BOLA, SSRF, error disclosure, comprehensive portal run, and a clean-page false-positive check. ElementScanner spec targets explicit locators for SQLi search and XSS firstname inputs (plus detector filtering via `testCategories`).
- Assertions: ≥1 finding per vuln page, confidence ≥0.7 (higher for traversal/SSRF), evidence req/resp present, correct CWE/OWASP tags, verification attempts present, clean page yields no non-info findings. ElementScanner spec also checks locator metadata and detector scoping.

### CSRF Coverage Note

**Important**: CSRF detection (e.g., `/csrf_3.php`) is **validated manually only** and is not covered by the automated detector suite. The manual testing in `tests/manual-findings-report.md` confirms CSRF vulnerabilities by checking for absence of CSRF tokens on POST forms, but automated CsrfDetector is not yet implemented. If you need automated CSRF validation, consider implementing a `CsrfDetector` under `src/detectors/active/`.

## Manual Scenarios (TSX scripts)
- `examples/bwapp-page-validation.ts`: runs all OWASP pages sequentially, logs findings, writes JSON/HTML reports under `test-security-reports/`.
- `examples/bwapp-sqli-focused.ts`: targets SQL injection pages.
- `examples/bwapp-xss-focused.ts`: targets XSS pages.

Run with:
```
BWAPP_URL=http://localhost:8080 npx tsx examples/bwapp-page-validation.ts
```
(Replace script name as needed.)

## TPR/FPR Metric Calculation

The suite supports automated calculation of True Positive Rate (TPR) and False Positive Rate (FPR) by comparing manual findings against automated scan results.

### Running the Metric Check

1. Ensure manual findings are recorded in `tests/manual/manual-findings.json`
2. Run automated scans to populate `tests/debug/scan-logs/`
3. Generate the comparison report and metrics:

```bash
npx tsx tests/debug/compare-results.ts
```

This outputs:
- `tests/debug/comparison-report.html` - Visual comparison report
- `tests/debug/metrics-summary.json` - Structured metrics with TPR/FPR percentages

### Metric Thresholds

The CI validation step asserts:
- **True Positive Rate (TPR)**: ≥ 90% (detects 90%+ of known vulnerabilities)
- **False Positive Rate (FPR)**: < 10% (less than 10% false alarms)

Run the metric validation:
```bash
npx tsx tests/debug/validate-metrics.ts
```

This complements (does not replace) the per-page Playwright assertions in `bwapp-validation.spec.ts`.

## Expected Results (baseline)
| Page | Detector | Expected Vuln | Min Confidence | Evidence Example |
|------|----------|---------------|----------------|------------------|
| sqli_1.php | SqlInjectionDetector | SQL Injection (CWE-89) | 0.80 | SQL error or boolean diff in response |
| sqli_6.php | SqlInjectionDetector | SQL Injection (CWE-89) | 0.70 | Login bypass / altered status |
| sqli_10-1.php | SqlInjectionDetector | SQL Injection (CWE-89) | 0.70 | JSON body reflects injection effect |
| xss_get.php | XssDetector | Reflected XSS (CWE-79) | 0.75 | Payload reflection containing `<script>` |
| xss_post.php | XssDetector | Reflected XSS (CWE-79) | 0.75 | POST body reflection in response |
| xss_stored_1.php | XssDetector | Stored XSS (CWE-79) | 0.80 | Persistent payload rendered |
| commandi.php | InjectionDetector | Command Injection (CWE-77) | 0.80 | OS command output (e.g., `uid=`) |
| directory_traversal_1.php | PathTraversalDetector | Path Traversal (CWE-22) | 0.85 | `/etc/passwd` content like `root:x:` |
| idor_1.php | BolaDetector | BOLA/IDOR (CWE-639) | 0.70 | Unauthorized record access |
| ssrf_1.php | SsrfDetector | SSRF (CWE-918) | 0.80 | Internal metadata/response |
| install.php | ErrorBasedDetector | Error Disclosure | 0.60 | Stack trace or verbose error |
| csrf_3.php | *(Manual only)* | CSRF (CWE-352) | N/A | Form accepts changes without CSRF token |

## Notes
- Ensure `storage-states/bwapp-auth.json` exists (run global setup) before tests/scripts.
- Reports are written to `test-security-reports/`. Clean this directory if you need fresh artifacts.
- Confidence targets are baselines; real results may vary slightly with environment latency.
- CSRF vulnerabilities are confirmed manually; automated CSRF detection is not yet implemented.
