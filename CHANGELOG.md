# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0-beta.1] - 2025-11-24

### 🎉 Initial Beta Release

The first public beta release of Playwright Security! This release includes core DAST scanning capabilities with Playwright integration.

### ✨ Added

#### Core Framework
- **ScanEngine**: Orchestration engine with parallel scanner execution
- **BrowserManager**: Playwright browser lifecycle management
- **ConfigurationManager**: JSON-based configuration with validation

#### Active Scanner
- **ActiveScanner**: Form-based vulnerability testing with payload injection
- **DomExplorer**: Intelligent attack surface discovery
- **PayloadInjector**: Smart payload injection with 1s timeout optimization

#### Detectors (Phase 3)
- **SqlInjectionDetector**: Comprehensive SQL injection detection
  - Error-based detection
  - Boolean-based blind SQL injection
  - Time-based blind SQL injection
  - Union-based SQL injection
  - CWE-89 | OWASP A03:2021

- **XssDetector**: Cross-site scripting detection
  - Reflected XSS
  - Stored XSS  
  - DOM-based XSS
  - CWE-79 | OWASP A03:2021

- **ErrorBasedDetector**: Information disclosure detection
  - Stack traces
  - Database errors
  - Path disclosure
  - Debug information
  - CWE-209 | OWASP A05:2021

#### Reporters (Phase 4)
- **ConsoleReporter**: Real-time colored output with ora spinner + chalk
- **JsonReporter**: Machine-readable JSON format
- **HtmlReporter**: Beautiful HTML reports with Handlebars templates
- **SarifReporter**: SARIF 2.1.0 for GitHub Security integration

#### CLI (Phase 5)
- Command-line interface with Commander.js
- `--config` flag for JSON configuration files
- Multiple output formats: `--formats console,json,html,sarif`
- Parallel execution: `--parallel <n>`
- Binary: `dast-scan` command

#### Playwright Integration
- **Testing Helpers**: `runSecurityScan()`, `assertNoVulnerabilities()`
- Example test files in `examples/` directory
- Support for inline security testing

#### CI/CD
- GitHub Actions workflow for SARIF upload
- Example workflows in `examples/`
- Automated NPM publishing on release

### 🚀 Performance
- 1-second timeout for element interactions (down from 30s)
- Selector-first approach (avoids stale element handles)
- Configurable parallelism (default: 2 concurrent scanners)
- Debug-level logging for failed injections (reduces noise)

### 📊 Coverage
- **CWE Coverage**: 3/250 (12%) - Initial set
  - CWE-89: SQL Injection
  - CWE-79: Cross-Site Scripting
  - CWE-209: Information Exposure Through Error Messages

### 📚 Documentation
- Comprehensive README with quick start
- Example configuration files
- Playwright test integration examples
- GitHub Actions CI/CD examples
- JSDoc comments on core APIs

### 🔧 Configuration
- JSON-based configuration files
- Environment-specific configs (dev, staging, prod)
- CLI args override config file values
- Default config in `config/default.config.json`

### 🛠️ Developer Experience
- TypeScript-first with full type definitions
- ESLint + Prettier configuration
- Jest for unit & integration tests
- Playwright for E2E tests
- NPM scripts for common tasks

### ⚙️ Technical Details
- **Node.js**: >=18.0.0
- **TypeScript**: 5.3
- **Playwright**: 1.56
- **Dependencies**: Minimal (commander, chalk, ora, handlebars, winston, uuid)

### 🐛 Known Issues
- Passive scanner not yet implemented (Phase 6)
- Limited to Chromium browser (Firefox/WebKit support planned)
- No authentication support yet
- Single-page scanning only (crawling basic)

### 📝 Migration Notes

This is the first beta release. Breaking changes expected in future versions.

**NPM Installation:**
```bash
npm install @tzigger/playwright-security@0.1.0-beta.1
```

**CLI Usage:**
```bash
npx dast-scan https://example.com --formats console,json,html
```

**Playwright Tests:**
```typescript
import { runSecurityScan, VulnerabilitySeverity } from '@tzigger/playwright-security';

test('security test', async ({ page }) => {
  const vulns = await runSecurityScan(page.url());
  expect(vulns.filter(v => v.severity === VulnerabilitySeverity.CRITICAL)).toHaveLength(0);
});
```

## [Unreleased]

### Planned for v0.2.0
- Passive scanner implementation
- CSRF detection
- Path traversal detection
- Command injection detection
- Authentication support (OAuth, Session-based)
- Multi-browser support (Firefox, WebKit)
- Performance optimizations (caching, smart crawling)
- Custom detector API

### Planned for v1.0.0
- Stable API
- 30%+ CWE coverage (75+/250)
- Production-ready passive scanner
- Full authentication support
- API security testing
- OpenAPI/Swagger integration
- Web UI for reports

---

[0.1.0-beta.1]: https://github.com/Tzigger/playwright_security/releases/tag/v0.1.0-beta.1
