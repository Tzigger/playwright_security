# DAST Security Scanner

> Automated Dynamic Application Security Testing (DAST) Engine using Playwright

![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
![TypeScript](https://img.shields.io/badge/TypeScript-5.3-blue.svg)
![Playwright](https://img.shields.io/badge/Playwright-1.56-orange.svg)

## 🎯 Overview

A powerful, modular, and extensible security testing framework that combines **passive network analysis** with **active vulnerability scanning** to detect security issues in web applications.

### Key Features

- 🔍 **Dual Scanning Modes**
  - **Passive Scanner**: Network traffic interception and analysis
  - **Active Scanner**: Input fuzzing and form manipulation

- 🛡️ **Comprehensive Detection**
  - SQL Injection
  - Cross-Site Scripting (XSS)
  - Command Injection
  - Sensitive Data Exposure
  - Insecure Transmission
  - Security Headers
  - And more...

- 🔌 **Plugin Architecture**
  - Custom scanners
  - Custom detectors
  - Extensible patterns

- 📊 **Multiple Report Formats**
  - JSON (machine-readable)
  - HTML (human-friendly)
  - SARIF (CI/CD integration)
  - Console (real-time)
  - Markdown

- ⚙️ **Highly Configurable**
  - Configuration profiles
  - Custom payloads
  - Scope management
  - Authentication support

## 🚀 Quick Start

### Installation

```bash
npm install
```

### Basic Usage

```bash
# Run a basic scan
npm run dev -- scan --url https://example.com

# Use a configuration file
npm run dev -- scan --config ./config/default.config.json

# Use a profile
npm run dev -- scan --url https://example.com --profile aggressive

# Passive scan only
npm run dev -- scan --url https://example.com --profile passive-only
```

### Programmatic Usage

```typescript
import { ScanEngine } from './src/core/engine/ScanEngine';
import { ConfigurationBuilder } from './src/core/config/ConfigurationBuilder';

// Build configuration
const config = new ConfigurationBuilder()
  .setTarget('https://example.com')
  .enablePassiveScanner()
  .enableActiveScanner('medium')
  .setReportFormats(['json', 'html'])
  .build();

// Run scan
const engine = new ScanEngine(config);
const results = await engine.run();

console.log(`Found ${results.vulnerabilities.length} vulnerabilities`);
```

## 📋 Architecture

### High-Level Design

```
┌─────────────────────────────────────────────────┐
│              CLI Interface Layer                 │
└─────────────────────────────────────────────────┘
                        │
┌─────────────────────────────────────────────────┐
│           Core Engine Layer                      │
│  ScanEngine │ BrowserManager │ ConfigManager    │
└─────────────────────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌──────────────────┐          ┌──────────────────┐
│ Passive Scanner  │          │  Active Scanner  │
└──────────────────┘          └──────────────────┘
        │                               │
        ▼                               ▼
┌──────────────────────────────────────────────────┐
│            Detector Layer (Strategy)             │
└──────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│           Reporting Layer                        │
└─────────────────────────────────────────────────┘
```

### Project Structure

```
src/
├── core/              # Core engine and interfaces
├── scanners/          # Passive and active scanners
├── detectors/         # Vulnerability detectors
├── reporters/         # Report generators
├── utils/             # Utilities and helpers
├── types/             # TypeScript type definitions
├── plugins/           # Plugin system
└── cli/               # CLI interface

config/                # Configuration files
├── default.config.json
├── profiles/          # Scan profiles
└── payloads/          # Attack payloads

docs/                  # Documentation
examples/              # Example usage
tests/                 # Test suites
```

## 🔧 Configuration

### Configuration File

Create a `config.json`:

```json
{
  "target": {
    "url": "https://example.com",
    "crawlDepth": 2,
    "maxPages": 50
  },
  "scanners": {
    "passive": {
      "enabled": true,
      "interceptTypes": ["xhr", "fetch", "document"]
    },
    "active": {
      "enabled": true,
      "aggressiveness": "medium",
      "payloadSets": ["sql-injection", "xss"]
    }
  },
  "reporting": {
    "formats": ["json", "html"],
    "outputDir": "./reports"
  }
}
```

### Profiles

Use pre-configured profiles:

- `passive-only` - Non-intrusive scanning
- `aggressive` - Comprehensive testing
- `quick-scan` - Fast vulnerability check

## 🔌 Plugin Development

Create custom detectors:

```typescript
import { BaseDetector } from './src/core/interfaces/IDetector';
import { Vulnerability, VulnerabilityCategory } from './src/types';

export class CustomDetector extends BaseDetector {
  readonly id = 'custom-detector';
  readonly name = 'Custom Vulnerability Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.CUSTOM;
  readonly description = 'Detects custom vulnerabilities';

  async detect(data: unknown): Promise<Vulnerability[]> {
    // Your detection logic here
    return [];
  }

  getPatterns(): RegExp[] {
    return [/your-pattern/gi];
  }
}
```

## 📊 Reports

### Sample Output

```
┌─────────────────────────────────────────────────┐
│          Security Scan Report                    │
├─────────────────────────────────────────────────┤
│ Target: https://example.com                      │
│ Duration: 2m 34s                                 │
│ Pages Scanned: 15                                │
├─────────────────────────────────────────────────┤
│ Vulnerabilities Found: 8                         │
│   Critical: 2                                    │
│   High: 3                                        │
│   Medium: 2                                      │
│   Low: 1                                         │
└─────────────────────────────────────────────────┘
```

## 🧪 Testing

```bash
# Run all tests
npm test

# Run specific test suites
npm run test:unit
npm run test:integration
npm run test:e2e

# Coverage report
npm run test:coverage
```

## 🛠️ Development

```bash
# Build the project
npm run build

# Watch mode
npm run build:watch

# Lint code
npm run lint
npm run lint:fix

# Format code
npm run format
npm run format:check
```

## 📚 Documentation

- [Architecture](./docs/architecture.md) - System design and patterns
- [Plugin Development](./docs/plugin-development.md) - Creating custom plugins
- [API Reference](./docs/api-reference.md) - Full API documentation

## 🤝 Contributing

Contributions are welcome! Please read our contributing guidelines before submitting PRs.

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is for authorized security testing only. Always obtain proper authorization before scanning any application you don't own.

## 🔗 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Playwright Documentation](https://playwright.dev/)
- [CWE Database](https://cwe.mitre.org/)

## 📧 Support

For issues and questions, please use the GitHub issue tracker.

---

**Built with ❤️ using TypeScript and Playwright**
