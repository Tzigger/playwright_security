# Safe Mode Architecture & Flow Diagrams

## 1. Safe Mode Processing Flow

```
User Configuration
        │
        ▼
┌──────────────────────┐
│   ScanEngine.scan()  │
└──────────────────────┘
        │
        ├─► TargetValidator.validateUrl()
        │   ├─► Detect environment (local/staging/production)
        │   ├─► Check HTTPS compliance
        │   ├─► Check port numbers
        │   └─► Return validation result + warnings
        │
        ├─► Is Non-Local Target?
        │   └─► YES: Auto-enable safe mode
        │
        ├─► Log warnings if production
        │
        ▼
┌──────────────────────────────────┐
│  ActiveScanner.testSqlInjection()│
└──────────────────────────────────┘
        │
        ├─► Get SQL_PAYLOADS list
        │
        ├─► Is safe mode enabled?
        │   ├─► YES: PayloadFilter.filterPayloads()
        │   │   ├─► Check each payload against patterns
        │   │   ├─► Remove dangerous payloads
        │   │   └─► Return safe payloads only
        │   │
        │   └─► NO: Use all payloads
        │
        ├─► Loop through payloads
        │
        ├─► For each payload:
        │   └─► ApiScanner.injectPayload() → Send to target
        │
        ▼
    Results
```

## 2. Payload Filtering Decision Tree

```
                    Payload String
                         │
                         ▼
        ┌────────────────────────────────┐
        │ PayloadFilter.isSafe()         │
        └────────────────────────────────┘
                         │
        ┌────────────────┴────────────────┐
        │                                  │
        ▼                                  ▼
  Check Dangerous            Check Dangerous
  Keywords                   Patterns
  (DROP, DELETE,etc)         (Regex matching)
        │                                  │
        ├─► Found?                        ├─► Matched?
        │   │                             │   │
        │   YES ──────────┐               │   YES ──────────┐
        │                  │               │                │
        │   NO ───────────┼───────────┐   │                │
        │                  │           │   NO ────────────┼┘
        │                  │           │                  │
        └──────────────────┴───────────┴──────────────────┘
                                  │
                                  ▼
                    ┌─────────────────────┐
                    │ Return: SAFE/DANGER │
                    └─────────────────────┘
                                  │
                    ┌─────────────┴─────────────┐
                    │                           │
                    ▼                           ▼
              SAFE (0.7)                  DANGEROUS (0.3)
              ├─ Allow injection          ├─ Block injection
              ├─ Continue test            ├─ Log blocked attempt
              └─ Report result            └─ Return error
```

## 3. Target Validation Flow

```
              Target URL
                  │
                  ▼
    ┌─────────────────────────┐
    │ Parse URL & Extract Host │
    └─────────────────────────┘
                  │
        ┌─────────┼─────────┬──────────┐
        │         │         │          │
        ▼         ▼         ▼          ▼
  Check Local  Check Stage  Check Prod  Unknown
  (localhost,  (.staging,   (.prod,    (other)
   127.0.0.1,  .stage,      public
   192.168.x,  .test,       domains)
   etc)        .qa, .dev)
        │         │         │          │
        ▼         ▼         ▼          ▼
    LOCAL    STAGING   PRODUCTION  UNKNOWN
        │         │         │          │
        └─────────┴─────────┴──────────┘
                  │
                  ▼
    ┌──────────────────────────────┐
    │ Validation Result            │
    ├──────────────────────────────┤
    │ - environment type           │
    │ - isLocal / isProduction     │
    │ - warnings (HTTPS, ports)    │
    │ - recommendations            │
    └──────────────────────────────┘
```

## 4. ScanEngine Pre-scan Validation

```
User calls engine.scan()
        │
        ▼
┌────────────────────────────────────┐
│ 1. Load Configuration              │
└────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────┐
│ 2. Validate Target URL             │
│    targetValidator.validateUrl()   │
└────────────────────────────────────┘
        │
        ▼
┌────────────────────────────────────┐
│ 3. Check Environment Type          │
│    Is it production?               │
└────────────────────────────────────┘
        │
    ┌───┴────┬──────────────────┐
    │        │                  │
   YES      NO               UNKNOWN
    │        │                  │
    ▼        ▼                  ▼
  [PROD]   [LOCAL]          [STAGING]
    │        │                  │
    ├─ Log   ├─ No warnings    ├─ Warn non-local
    │  warn  └─ Full testing   ├─ Auto-enable
    │        Possible          │  safe mode
    ├─ Check                   └─ Check HTTPS
    │  HTTPS                      (warn if HTTP)
    ├─ Check
    │  ports
    └─► Auto-enable safe mode
        (if active scanning)
        │
        ▼
    Ready for scan!
```

## 5. Scanner Initialization with Safe Mode

```
User creates scanner
        │
        ▼
┌────────────────────────────────┐
│ new PayloadInjector(           │
│   logLevel,                    │
│   safeMode = false             │
│ )                              │
└────────────────────────────────┘
        │
        ├─► Instantiate PayloadFilter
        │
        ├─► Set this.safeMode = safeMode
        │
        └─► Log safe mode status
            (if enabled)
                │
                ▼
        Injector ready!
        Can accept:
        ├─ inject(payload)
        ├─ generateFuzzingPayloads()
        └─ setSafeMode(enabled)
```

## 6. Injection with Safe Mode Check

```
User calls injector.inject(payload)
        │
        ▼
┌──────────────────────────┐
│ Check: Is safe mode on? │
└──────────────────────────┘
        │
    ┌───┴───────────────┐
    │                   │
   YES                 NO
    │                   │
    ▼                   ▼
Check payload    Proceed with
safety           injection
    │              │
    ├─► Safe?      └─► Inject payload
    │   │             │
    │  YES            ├─► Monitor response
    │   │             │
    │   ├─► Inject    └─► Verify behavior
    │   │
    │   NO
    │   │
    │   └─► Block!
    │       ├─ Log blocked attempt
    │       ├─ Return error in result
    │       └─ Do NOT execute payload
    │
    └──► Return injection result
         (success or blocked)
```

## 7. Payload Filtering Statistics

```
Total Payloads: 25
    │
    ├─► PayloadFilter.getFilterStats()
    │
    ├─► Categorize each:
    │   ├─ SAFE:     20
    │   ├─ WARNING:   2
    │   └─ DANGER:    3
    │
    ▼
Statistics Report:
┌──────────────────────────┐
│ total:      25           │
│ safe:       20 (80%)     │
│ warning:     2 (8%)      │
│ dangerous:   3 (12%)     │
└──────────────────────────┘
    │
    ▼
Used in safe mode:
├─ All SAFE payloads: 20
├─ Remove DANGER: -3
├─ Result: 20 payloads
└─ Log: "Filtered 3 dangerous"
```

## 8. Configuration Propagation

```
default.config.json
    │
    ├─ scanners.active.safeMode = false
    │
    ▼
User loads config
    │
    ▼
ConfigurationManager
    │
    ▼
ScanEngine
    │
    ├─► Check environment
    │   └─► If production: auto-override to true
    │
    ▼
Passed to scanners:
    ├─ PayloadInjector(logLevel, safeMode)
    ├─ ApiScanner(..., safeMode)
    └─ ActiveScanner(..., safeMode)
    │
    ▼
Each scanner:
    └─ Instantiates PayloadFilter
    └─ Applies filtering when enabled
```

## 9. Error Handling Flow

```
User provides destructive payload
        │
        ▼
PayloadInjector.inject(payload)
        │
        ├─► Check safe mode
        │   └─► ENABLED
        │
        ├─► Check payload safety
        │   └─► PayloadFilter.isSafe()
        │       └─► Returns FALSE
        │
        ▼
┌─────────────────────────────┐
│ BLOCK PAYLOAD               │
├─────────────────────────────┤
│ Actions:                    │
│ 1. Log warning              │
│ 2. Return error in result   │
│ 3. Do NOT execute payload   │
│ 4. Continue with next test  │
└─────────────────────────────┘
        │
        ▼
Return to caller:
{
  payload: "...blocked payload...",
  error: "Payload blocked by safe mode - contains destructive operations",
  surface: {...}
}
        │
        ▼
Caller handles error:
├─ Log it
├─ Move to next payload
└─ Continue scanning
```

## 10. Audit Trail & Logging

```
Scan begins on production.example.com
        │
        ▼
[TargetValidator] Validated target: production.example.com (production)
        │
        ▼
[ScanEngine] Target is non-local (non-localhost). 
             Automatically enabling safe mode...
        │
        ▼
[PayloadInjector] SafeMode ENABLED: 
                  Destructive payloads will be filtered
        │
        ▼
Testing SQL injection...
        │
        ├─► [PayloadFilter] Filtered out 5 destructive payload(s) 
        │                   in safe mode. (18/23 payloads remain safe)
        │
        ├─► [Inject] Payload 1: ' OR '1'='1 (SAFE)
        │
        ├─► [Inject] Payload 2: '; DROP TABLE users-- (BLOCKED - Safe Mode)
        │
        └─► [PayloadInjector] BLOCKED (Safe Mode): 
                              Destructive payload attempt
        │
        ▼
Scan complete!
```

## Legend

```
┌────┐     Box: Process/Component
├────┤     Lines: Data/Control flow
│    │     Arrows: Direction of flow
└────┘     
│          Vertical pipe: Sequential flow
└─ Horizontal: Branching/conditions
├─ Left/Right: Alternative paths
▼  Arrow: Next step
────────── Bold: Important operations
```

## Key Integration Points

```
┌────────────────────────────────────────────────────┐
│                   ScanEngine                        │
├────────────────────────────────────────────────────┤
│                                                    │
│  ┌──────────────┐      ┌──────────────┐           │
│  │TargetValidat│      │PayloadFilter │           │
│  │or            │      │              │           │
│  └──────────────┘      └──────────────┘           │
│       │ Validates              │ Filters          │
│       │ environment            │ payloads         │
│       │                        │                  │
│       ▼                        ▼                  │
│  ┌────────────────────────────────────┐          │
│  │  Scanners                          │          │
│  ├────────────────────────────────────┤          │
│  │ - PayloadInjector                  │          │
│  │ - ApiScanner                       │          │
│  │ - ActiveScanner                    │          │
│  └────────────────────────────────────┘          │
│       │                                          │
│       └─► All use PayloadFilter                  │
│       └─► All respect safe mode                  │
│                                                  │
└────────────────────────────────────────────────────┘
```

---

**Note**: These diagrams show the logical flow. Actual implementation uses async/await and event-based patterns, but the overall flow is as depicted above.
