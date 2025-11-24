# Examples & Integration Patterns

This directory contains examples showing how to use the Playwright Security Framework in different scenarios.

## 📁 Files

- **`dast.config.json`** - Example configuration file for CLI scanning
- **`playwright-test-integration.spec.ts`** - Playwright test integration examples
- **`github-actions-ci.yml`** - GitHub Actions CI/CD workflow

## 🚀 Quick Start

### 1. CLI Scanning with Config File

```bash
# Use the example config
dast-scan --config examples/dast.config.json

# Override specific settings
dast-scan --config examples/dast.config.json https://example.com --parallel 4
```

### 2. Playwright Test Integration

```typescript
import { test, expect } from '@playwright/test';
import { runSecurityScan, VulnerabilitySeverity } from 'playwright_security';

test('login should be secure', async ({ page }) => {
  await page.goto('https://myapp.com/login');
  
  const vulns = await runSecurityScan(page.url());
  
  const critical = vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
  expect(critical).toHaveLength(0);
});
```

### 3. CI/CD Integration (GitHub Actions)

Copy `github-actions-ci.yml` to `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: npm ci
      - run: npx playwright install chromium
      - run: npx dast-scan $STAGING_URL --formats sarif
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/*.sarif
```

## 📊 Use Cases

### Use Case 1: Pre-deployment Security Check

```bash
# Run before deploying to production
dast-scan https://staging.myapp.com \
  --config dast.config.json \
  --formats sarif,html \
  --output ./pre-deploy-scan

# Check for critical issues
if grep -q '"severity": "critical"' pre-deploy-scan/*.json; then
  echo "❌ Critical vulnerabilities found - deployment blocked"
  exit 1
fi
```

### Use Case 2: Developer Workflow

```bash
# Quick scan during development
dast-scan http://localhost:3000 \
  --formats console \
  --parallel 1 \
  --max-pages 5
```

### Use Case 3: Scheduled Security Audits

```yaml
# .github/workflows/weekly-audit.yml
on:
  schedule:
    - cron: '0 2 * * 1' # Every Monday at 2 AM

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - run: dast-scan $PRODUCTION_URL --formats html,sarif
      - name: Email results
        run: send-email --attachment reports/*.html
```

## 🔧 Configuration Tips

### Environment-Specific Configs

```bash
# Development
dast-scan --config dast.dev.config.json

# Staging
dast-scan --config dast.staging.config.json

# Production (less aggressive)
dast-scan --config dast.prod.config.json
```

### Custom Detector Selection

```json
{
  "detectors": {
    "enabled": ["sql-injection", "xss"],
    "sensitivity": "high"
  }
}
```

## 📝 Best Practices

1. **Start with low aggressiveness** in production
2. **Use SARIF format** for CI/CD integration
3. **Set scan timeouts** appropriately for large apps
4. **Exclude logout/delete endpoints** from scanning
5. **Run scans in headless mode** in CI/CD
6. **Store reports** as artifacts for historical analysis

## 🆘 Troubleshooting

**Scan too slow?**
- Reduce `maxPages` and `crawlDepth`
- Increase `parallelism`
- Enable `skipStaticResources`

**Too many false positives?**
- Increase `minConfidence` threshold
- Adjust `sensitivity` to "normal" or "low"
- Use custom detector configuration

**CI/CD pipeline failing?**
- Set `continue-on-error: true` initially
- Review findings and adjust severity thresholds
- Use `--formats sarif` for integration with security tools

## 📚 Learn More

- [Main Documentation](../README.md)
- [API Reference](../docs/API.md)
- [Configuration Guide](../docs/CONFIGURATION.md)
