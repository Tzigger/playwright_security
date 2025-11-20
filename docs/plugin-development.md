# Plugin Development Guide

## Overview

The DAST Engine supports custom plugins for extending functionality. You can create:

- Custom scanners
- Custom detectors
- Custom reporters

## Creating a Custom Detector

### 1. Basic Structure

```typescript
import { BaseDetector } from '../src/core/interfaces/IDetector';
import { Vulnerability, VulnerabilityCategory, VulnerabilitySeverity } from '../src/types';

export class MyCustomDetector extends BaseDetector {
  readonly id = 'my-custom-detector';
  readonly name = 'My Custom Detector';
  readonly version = '1.0.0';
  readonly category = VulnerabilityCategory.CUSTOM;
  readonly description = 'Detects custom security issues';
  
  async detect(data: unknown): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Your detection logic here
    
    return vulnerabilities;
  }
  
  getPatterns(): RegExp[] {
    return [
      /pattern1/gi,
      /pattern2/gi,
    ];
  }
  
  getCWEReferences(): string[] {
    return ['CWE-79', 'CWE-89'];
  }
  
  getOWASPReferences(): string[] {
    return ['A03:2021'];
  }
}
```

### 2. Detection Logic Example

```typescript
async detect(data: unknown): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  
  // Type guard
  if (typeof data !== 'string') {
    return vulnerabilities;
  }
  
  // Pattern matching
  const patterns = this.getPatterns();
  for (const pattern of patterns) {
    const matches = data.match(pattern);
    
    if (matches && matches.length > 0) {
      const vulnerability = this.createVulnerability({
        title: 'Custom Vulnerability Detected',
        description: `Found suspicious pattern: ${matches[0]}`,
        severity: VulnerabilitySeverity.HIGH,
        evidence: {
          url: 'https://example.com',
          responseBody: data.substring(0, 500),
        },
        remediation: 'Remove or sanitize the detected pattern',
        confidence: 0.8,
        cwe: 'CWE-200',
        owasp: 'A01:2021',
        references: [
          'https://owasp.org/www-project-top-ten/',
        ],
      });
      
      vulnerabilities.push(vulnerability);
    }
  }
  
  return vulnerabilities;
}
```

### 3. Advanced Validation

```typescript
async validate(vulnerability: Vulnerability): Promise<boolean> {
  // Custom validation logic
  if (vulnerability.confidence < 0.6) {
    return false;
  }
  
  // Additional checks
  const evidence = vulnerability.evidence;
  if (!evidence.responseBody) {
    return false;
  }
  
  // Confirm with additional analysis
  return await this.confirmVulnerability(evidence);
}

private async confirmVulnerability(evidence: Evidence): Promise<boolean> {
  // Secondary confirmation logic
  return true;
}
```

## Creating a Custom Scanner

### 1. Basic Structure

```typescript
import { BaseScanner } from '../src/scanners/base/BaseScanner';
import { ScanResult, ScanStatus } from '../src/types';

export class MyCustomScanner extends BaseScanner {
  readonly id = 'my-custom-scanner';
  readonly name = 'My Custom Scanner';
  readonly version = '1.0.0';
  readonly type = 'active';
  readonly description = 'Custom security scanner';
  
  async execute(): Promise<ScanResult> {
    const context = this.getContext();
    const startTime = new Date();
    
    // Your scanning logic
    const vulnerabilities = await this.performScan();
    
    return {
      scanId: this.generateScanId(),
      scannerId: this.id,
      scannerName: this.name,
      scannerType: this.type,
      startTime,
      endTime: new Date(),
      duration: Date.now() - startTime.getTime(),
      targetUrl: context.config.target.url,
      status: ScanStatus.COMPLETED,
      vulnerabilities,
      statistics: this.calculateStatistics(),
      metadata: {},
    };
  }
  
  private async performScan(): Promise<Vulnerability[]> {
    // Implement your scanning logic
    return [];
  }
}
```

### 2. Integration with Detectors

```typescript
private async performScan(): Promise<Vulnerability[]> {
  const context = this.getContext();
  const vulnerabilities: Vulnerability[] = [];
  
  // Register your detector
  const detector = new MyCustomDetector();
  
  // Collect data
  const data = await this.collectData();
  
  // Run detection
  const detected = await detector.detect(data);
  vulnerabilities.push(...detected);
  
  return vulnerabilities;
}
```

## Creating a Custom Reporter

### 1. Basic Structure

```typescript
import { BaseReporter } from '../src/reporters/base/BaseReporter';
import { AggregatedScanResult, ReportFormat } from '../src/types';

export class MyCustomReporter extends BaseReporter {
  readonly id = 'my-custom-reporter';
  readonly name = 'My Custom Reporter';
  readonly format = ReportFormat.CUSTOM;
  readonly extension = 'custom';
  
  async generate(results: AggregatedScanResult, outputPath: string): Promise<void> {
    // Validate output path
    await this.validateOutputPath(outputPath);
    
    // Generate report content
    const reportContent = this.generateReportContent(results);
    
    // Write to file
    await this.writeFile(outputPath, reportContent);
  }
  
  private generateReportContent(results: AggregatedScanResult): string {
    // Your report generation logic
    return JSON.stringify(results, null, 2);
  }
}
```

## Plugin Registration

### 1. Manual Registration

```typescript
import { PluginRegistry } from './src/core/registry/PluginRegistry';
import { MyCustomDetector } from './plugins/MyCustomDetector';

const registry = new PluginRegistry();
registry.registerDetector(new MyCustomDetector());
```

### 2. Auto-Discovery

Place your plugin in `src/plugins/` directory:

```
src/plugins/
  my-custom-detector/
    index.ts
    MyCustomDetector.ts
    README.md
```

## Plugin Metadata

Add metadata to your plugin:

```typescript
export const metadata: PluginMetadata = {
  id: 'my-custom-detector',
  name: 'My Custom Detector',
  version: '1.0.0',
  type: 'detector',
  author: 'Your Name',
  description: 'Detects custom vulnerabilities',
  homepage: 'https://github.com/yourname/plugin',
  repository: 'https://github.com/yourname/plugin',
  license: 'MIT',
  tags: ['custom', 'security'],
  minEngineVersion: '0.1.0',
};
```

## Testing Your Plugin

```typescript
import { MyCustomDetector } from './MyCustomDetector';

describe('MyCustomDetector', () => {
  let detector: MyCustomDetector;
  
  beforeEach(() => {
    detector = new MyCustomDetector();
  });
  
  it('should detect vulnerabilities', async () => {
    const data = 'test data with pattern';
    const results = await detector.detect(data);
    
    expect(results.length).toBeGreaterThan(0);
    expect(results[0].category).toBe(VulnerabilityCategory.CUSTOM);
  });
  
  it('should return correct patterns', () => {
    const patterns = detector.getPatterns();
    expect(patterns.length).toBeGreaterThan(0);
  });
});
```

## Best Practices

1. **Error Handling**: Always wrap detection logic in try-catch
2. **Performance**: Avoid expensive operations in tight loops
3. **Confidence Scoring**: Provide accurate confidence scores
4. **Documentation**: Document your patterns and logic
5. **Testing**: Write comprehensive unit tests
6. **Validation**: Implement proper validation to reduce false positives
7. **Logging**: Use the provided logger for debugging

## Example: Complete Custom Detector

See `src/plugins/examples/CustomDetectorPlugin.ts` for a complete example.

## Publishing Your Plugin

1. Create NPM package
2. Add peer dependencies
3. Document usage
4. Publish to NPM registry
5. Share on GitHub

## Support

For questions about plugin development, open an issue on GitHub.
