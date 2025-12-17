# Safe Mode & Production Guardrails

This document describes the safety features and production guardrails implemented in Kinetic to prevent accidental damage to target systems during security testing.

## Overview

Kinetic includes multiple safety mechanisms to prevent destructive operations on production environments:

1. **Safe Mode Flag** - Disables destructive payloads during active scanning
2. **Payload Filtering** - Removes dangerous SQL/command payloads automatically
3. **Target Validation** - Detects and warns about production targets
4. **Auto-enablement** - Automatically enables safe mode on non-local targets
5. **Configuration Guards** - Enforces safe defaults for production environments

## Safe Mode Configuration

### Enabling Safe Mode

Safe mode can be enabled in your configuration:

```json
{
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true,
      "aggressiveness": "medium"
    }
  }
}
```

Or programmatically:

```typescript
import { PayloadInjector } from '@tzigger/kinetic';

const injector = new PayloadInjector(LogLevel.INFO, true); // Safe mode enabled
injector.setSafeMode(true);
```

### CLI Configuration

When using the CLI, you can bypass Safe Mode using the `--safemode-disable` flag. This is dangerous and should only be used if you have explicit authorization to perform destructive tests on the target.

```bash
# Force disable safe mode for a remote target
npm start -- http://example.com --active --safemode-disable
```

### Configuration File

When **safeMode** is enabled:

- ✅ **Blocks destructive payloads** containing:
  - `DROP TABLE`, `DROP DATABASE`, `DELETE FROM`, `TRUNCATE`
  - `ALTER TABLE` (schema modifications)
  - `EXEC xp_cmdshell` and similar system command execution
  - `INSERT INTO` and `UPDATE` statements that modify data
  - File operations (`INTO OUTFILE`, `LOAD_FILE`, etc.)
  - Privilege escalation (`GRANT`, `REVOKE`)

- ✅ **Allows informational payloads** for vulnerability detection:
  - SQL injection detection (OR, UNION, ORDER BY, etc.)
  - Time-based blind SQL injection (SLEEP, WAITFOR, BENCHMARK)
  - Boolean-based blind SQL injection
  - XSS payloads (script injection, event handlers)
  - NoSQL injection probes
  - Path traversal testing

- ✅ **Logs all filtered payloads** for audit purposes

## Destructive Payload Filtering

### PayloadFilter Utility

The `PayloadFilter` utility detects and filters dangerous payloads:

```typescript
import { PayloadFilter } from '@tzigger/kinetic';

const filter = new PayloadFilter();

// Check if a single payload is safe
const isSafe = filter.isSafe("' OR '1'='1");  // true
const isDangerous = filter.isSafe("'; DROP TABLE users--"); // false

// Filter a list of payloads
const safePayloads = filter.filterPayloads(allPayloads);

// Get safety level
const level = filter.getSafetyLevel(payload);
// Returns: 'safe' | 'warning' | 'dangerous'

// Get filtering statistics
const stats = filter.getFilterStats(payloads);
// Returns: { total, safe, dangerous, warning }
```

### Dangerous Keywords

Safe mode blocks payloads containing these keywords:

**SQL Commands:**
- DROP, DELETE, TRUNCATE, ALTER, CREATE, INSERT, UPDATE
- EXEC, EXECUTE, GRANT, REVOKE

**System Execution:**
- xp_cmdshell, xp_dirtree, system(), shell_exec, exec()

**File Operations:**
- INTO OUTFILE, INTO DUMPFILE, LOAD_FILE, chmod, mkdir

**Process Control:**
- waitfor, sleep, benchmark, randomblob

## Target Validation

### TargetValidator Utility

The `TargetValidator` automatically detects target environment types:

```typescript
import { TargetValidator } from '@tzigger/kinetic';

const validator = new TargetValidator();

// Validate a target URL
const result = validator.validateUrl('https://myapp.com/login');

// Returns:
// {
//   isValid: boolean,
//   environment: 'local' | 'staging' | 'production' | 'unknown',
//   isProduction: boolean,
//   isLocal: boolean,
//   warnings: string[],
//   recommendations: string[]
// }

// Check if scanning should be blocked
const check = validator.shouldBlockActiveScan(
  'https://production.example.com',
  { confirmProduction: false }
);
// { shouldBlock: true, reason: '...' }

// Get a formatted summary
const summary = validator.getSummary(url);
console.log(summary);
```

### Environment Detection

Targets are automatically categorized:

**Local:**
- localhost, 127.0.0.1
- Private IP ranges (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
- IPv6 localhost (::1)

**Staging:**
- Contains `.staging.`, `.stage.`, `.test.`, `.qa.`, `.dev.`

**Production:**
- Contains `.production.`, `.prod.`
- Public domain names
- Non-standard ports (3000, 5000, 8000, 8080, etc.) get warnings

**Unknown:**
- Other targets

## Auto-enablement of Safe Mode

The ScanEngine automatically enables safe mode for non-local targets:

```typescript
const engine = new ScanEngine();
await engine.loadConfiguration(config);

// Scanning https://production.myapp.com
// Safe mode is AUTOMATICALLY ENABLED even if config.safeMode = false
const result = await engine.scan();
```

This prevents accidental data loss due to configuration mistakes.

## Production Guardrails

### Pre-scan Validation

Before starting a scan, Kinetic:

1. ✅ Validates the target URL format
2. ✅ Detects the environment type (local/staging/production)
3. ✅ Checks for HTTPS on production targets
4. ✅ Warns about non-standard ports
5. ✅ Logs security warnings for non-local active scans
6. ✅ Auto-enables safe mode for non-local targets

### Console Output

When scanning a non-local target:

```
[ScanEngine] SECURITY WARNING: Active scanning is enabled on production target.
[ScanEngine] Ensure you have explicit permission to perform active security testing on
              https://production.myapp.com
[TargetValidator] Target is production (not local)
[PayloadFilter] SafeMode ENABLED: Destructive payloads will be filtered
```

## Best Practices

### 1. Local Testing First

Always test on localhost first:

```json
{
  "target": {
    "url": "http://localhost:3000"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": false
    }
  }
}
```

### 2. Staging with Safe Mode

For staging environments, enable safe mode:

```json
{
  "target": {
    "url": "https://staging.myapp.com"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true
    }
  }
}
```

### 3. Production (Passive Only)

For production, use passive scanning only:

```json
{
  "target": {
    "url": "https://production.myapp.com"
  },
  "scanners": {
    "passive": {
      "enabled": true
    },
    "active": {
      "enabled": false
    }
  }
}
```

### 4. Explicit Production Approval

If you must do active scanning on production, be explicit:

```typescript
const config = loadConfig('production.config.json');
config.scanners.active.safeMode = true; // MUST be enabled
config.scanners.active.aggressiveness = 'low';
config.target.url = 'https://production.myapp.com';

// Add explicit approval check
if (approvedForProductionTesting) {
  const engine = new ScanEngine();
  await engine.loadConfiguration(config);
  const result = await engine.scan();
}
```

## Audit & Compliance

### Payload Filtering Logs

All filtered payloads are logged with details:

```
[PayloadFilter] Filtered out 5 destructive payload(s) in safe mode. (18/23 payloads remain safe)
[PayloadInjector] BLOCKED (Safe Mode): Destructive payload attempt - '; DROP TABLE users--...
```

### Target Validation Logs

Target validation is logged for audit trails:

```
[TargetValidator] Validated target: production.myapp.com (production) - 
                  isLocal: false, isProduction: true
[ScanEngine] === Target Validation Summary ===
[ScanEngine] URL: https://production.myapp.com
[ScanEngine] Environment: production
[ScanEngine] Production Target: Yes
[ScanEngine] Warnings:
[ScanEngine]   1. Target is production (not local)
[ScanEngine] Recommendations:
[ScanEngine]   1. Active scanning on non-local targets requires explicit confirmation
[ScanEngine]   2. Consider using safe mode (safeMode: true) for non-local targets
```

## Configuration Reference

### Safe Mode Config Options

```typescript
interface ActiveScannerConfig {
  // ... other options ...
  
  /** Safe mode: disable destructive payloads that could damage the target */
  safeMode?: boolean;  // default: false (auto-enabled for non-local targets)
}
```

### Default Payload File Changes

The `config/payloads/sql-injection.txt` file has been updated:

- ✅ All destructive SQL statements are commented out
- ✅ Safe injection detection payloads remain active
- ✅ Clear header marking destructive vs. safe sections

## Troubleshooting

### "Payload blocked by safe mode" Error

This means you're trying to inject a destructive payload while safe mode is enabled. This is the intended behavior.

**Solution:** Only use this payload on localhost development environments with `safeMode: false`.

### Safe mode enabled unexpectedly

If safe mode is enabled when you don't expect it:

1. Check if you're scanning a non-local target
2. Check the ScanEngine logs for auto-enablement message
3. Explicitly set `safeMode: false` if you understand the risks

### Filter statistics don't match

Use `PayloadFilter.getFilterStats()` to understand:

```typescript
const stats = filter.getFilterStats(payloads);
console.log(`Safe: ${stats.safe}, Warning: ${stats.warning}, Dangerous: ${stats.dangerous}`);
```

## Related Features

- **Passive Scanning**: No payload injection, safe for production
- **Scope Configuration**: Limit scanning to specific URLs
- **Rate Limiting**: Reduce impact of active scanning
- **Timeout Settings**: Prevent long-running operations
- **Browser Headless Mode**: Avoid unnecessary resource usage

## Further Reading

- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Responsible Vulnerability Disclosure](https://owasp.org/www-community/Responsible_Disclosure)
- [PCI DSS Compliance](https://www.pcisecuritystandards.org/)
