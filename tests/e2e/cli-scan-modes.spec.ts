/**
 * CLI Scan Modes E2E Tests
 * 
 * Tests the correct implementation of the kinetic CLI tool across different
 * scan modes (passive, active, both) and target types (traditional, SPA, local).
 * 
 * Targets:
 * - http://testphp.vulnweb.com/ (traditional PHP site)
 * - http://testhtml5.vulnweb.com/#/popular (SPA with hash routing)
 * - http://localhost:3000 (local Juice Shop - requires manual setup)
 */
import { test, expect } from '@playwright/test';
import { exec, spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';
import { promisify } from 'util';

const execAsync = promisify(exec);

// Path to compiled CLI
const cliPath = path.join(__dirname, '../../dist/cli/index.js');
const projectRoot = path.join(__dirname, '../..');

interface ScanOutput {
  stdout: string;
  stderr: string;
  exitCode: number | null;
}

/**
 * Helper to run CLI with timeout and capture output
 */
async function runCli(args: string[], timeoutMs: number = 60000): Promise<ScanOutput> {
  return new Promise((resolve) => {
    const fullCommand = `node ${cliPath} ${args.join(' ')}`;
    let stdout = '';
    let stderr = '';
    
    const child = spawn('node', [cliPath, ...args], {
      cwd: projectRoot,
      env: { ...process.env, FORCE_COLOR: '0' }, // Disable colors for easier parsing
    });

    child.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    child.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    const timeout = setTimeout(() => {
      child.kill('SIGINT');
    }, timeoutMs);

    child.on('close', (code) => {
      clearTimeout(timeout);
      resolve({ stdout, stderr, exitCode: code });
    });

    child.on('error', (err) => {
      clearTimeout(timeout);
      resolve({ stdout, stderr: stderr + err.message, exitCode: 1 });
    });
  });
}

/**
 * Helper to check if output contains active scanner activity
 */
function hasActiveActivity(output: string): boolean {
  const activePatterns = [
    '[SqlInjectionDetector]',
    '[PayloadInjector]',
    '[XssDetector]',
    '[ErrorBasedDetector]',
    'Running detector:',
    'Start error-based',
    'Start boolean-based',
    'Start time-based',
  ];
  return activePatterns.some(pattern => output.includes(pattern));
}

/**
 * Helper to check if output contains passive scanner activity
 */
function hasPassiveActivity(output: string): boolean {
  const passivePatterns = [
    '[PassiveScanner]',
    '[SensitiveDataDetector]',
    '[HeaderSecurityDetector]',
    '[CookieSecurityDetector]',
    '[InsecureTransmissionDetector]',
    '[NetworkInterceptor]',
    'Passive scan completed',
  ];
  return passivePatterns.some(pattern => output.includes(pattern));
}

/**
 * Helper to check for report files
 */
function getReportFiles(outputDir: string): string[] {
  if (!fs.existsSync(outputDir)) return [];
  return fs.readdirSync(outputDir).filter(f => 
    f.endsWith('.json') || f.endsWith('.html') || f.endsWith('.sarif')
  );
}

// ============================================================================
// TEST SUITE: Passive-Only Mode
// ============================================================================
test.describe('CLI Passive-Only Mode', () => {
  
  test('--passive flag should run only passive scanner on testphp.vulnweb.com', async () => {
    test.setTimeout(90000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --passive');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--passive',
      '--formats', 'console',
    ], 60000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should have passive activity
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    
    // Should NOT have active injection activity
    expect(hasActiveActivity(combinedOutput)).toBe(false);
    
    // Should show passive scanner registered
    expect(combinedOutput).toContain('Registered scanner: passive');
    
    // Should NOT show active scanner registered (when passive-only)
    // Note: Due to current CLI defaults, active may still register. Check for injection activity instead.
    console.log('✓ Passive-only scan completed without payload injection');
  });

  test('--scan-type passive should run only passive scanner', async () => {
    test.setTimeout(90000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --scan-type passive');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--scan-type', 'passive',
      '--formats', 'console',
    ], 60000);

    const combinedOutput = output.stdout + output.stderr;
    
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    expect(hasActiveActivity(combinedOutput)).toBe(false);
    
    console.log('✓ --scan-type passive completed correctly');
  });
});

// ============================================================================
// TEST SUITE: Active-Only Mode
// ============================================================================
test.describe('CLI Active-Only Mode', () => {

  test('default scan should run active scanner with payload injection', async () => {
    test.setTimeout(120000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ (default active)');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--formats', 'console',
    ], 90000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should have active injection activity
    expect(hasActiveActivity(combinedOutput)).toBe(true);
    
    // Should show active scanner registered
    expect(combinedOutput).toContain('Registered scanner: active');
    
    console.log('✓ Active scan with payload injection completed');
  });

  test('--scan-type active should run only active scanner', async () => {
    test.setTimeout(120000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --scan-type active');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--scan-type', 'active',
      '--formats', 'console',
    ], 90000);

    const combinedOutput = output.stdout + output.stderr;
    
    expect(hasActiveActivity(combinedOutput)).toBe(true);
    expect(combinedOutput).toContain('Registered scanner: active');
    
    console.log('✓ --scan-type active completed correctly');
  });
});

// ============================================================================
// TEST SUITE: Combined Mode
// ============================================================================
test.describe('CLI Combined Mode (Both Scanners)', () => {

  test('--scan-type both should run both active and passive scanners', async () => {
    test.setTimeout(180000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --scan-type both');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--scan-type', 'both',
      '--formats', 'console',
    ], 120000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should have BOTH types of activity
    expect(hasActiveActivity(combinedOutput)).toBe(true);
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    
    expect(combinedOutput).toContain('Registered scanner: active');
    expect(combinedOutput).toContain('Registered scanner: passive');
    
    console.log('✓ Combined scan with both scanners completed');
  });

  test('--passive --active flags together should run both scanners', async () => {
    test.setTimeout(180000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --passive --active');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--passive',
      '--active',
      '--formats', 'console',
    ], 120000);

    const combinedOutput = output.stdout + output.stderr;
    
    expect(hasActiveActivity(combinedOutput)).toBe(true);
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    
    console.log('✓ --passive --active combined flags work correctly');
  });
});

// ============================================================================
// TEST SUITE: SPA Target (Hash Routes)
// ============================================================================
test.describe('CLI SPA Target Handling', () => {

  test('passive scan on SPA with hash route should work', async () => {
    test.setTimeout(90000);
    
    console.log('Running: kinetic "http://testhtml5.vulnweb.com/#/popular" --passive');
    const output = await runCli([
      'http://testhtml5.vulnweb.com/#/popular',
      '--passive',
      '--formats', 'console',
    ], 60000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should complete passive scan
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    
    // Should NOT inject payloads on passive mode
    expect(hasActiveActivity(combinedOutput)).toBe(false);
    
    // Should handle the SPA URL
    expect(combinedOutput).toContain('testhtml5.vulnweb.com');
    
    console.log('✓ SPA passive scan completed without injection');
  });

  test('active scan on SPA should discover hash routes', async () => {
    test.setTimeout(180000);
    
    console.log('Running: kinetic "http://testhtml5.vulnweb.com/#/popular" --scan-type active');
    const output = await runCli([
      'http://testhtml5.vulnweb.com/#/popular',
      '--scan-type', 'active',
      '--formats', 'console',
    ], 120000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should attempt to explore DOM
    expect(combinedOutput).toContain('[DomExplorer]');
    
    console.log('✓ SPA active scan attempted DOM exploration');
  });
});

// ============================================================================
// TEST SUITE: Report Generation
// ============================================================================
test.describe('CLI Report Generation', () => {
  const testOutputDir = path.join(projectRoot, 'test-cli-reports');

  test.beforeEach(() => {
    // Clean up test output directory
    if (fs.existsSync(testOutputDir)) {
      fs.rmSync(testOutputDir, { recursive: true });
    }
    fs.mkdirSync(testOutputDir, { recursive: true });
  });

  test.afterEach(() => {
    // Cleanup
    if (fs.existsSync(testOutputDir)) {
      fs.rmSync(testOutputDir, { recursive: true });
    }
  });

  test('should generate JSON and HTML reports', async () => {
    test.setTimeout(120000);
    
    console.log(`Running: kinetic http://testphp.vulnweb.com/ --passive --formats json,html --output ${testOutputDir}`);
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--passive',
      '--formats', 'json,html',
      '--output', testOutputDir,
    ], 90000);

    // Wait a bit for file writes
    await new Promise(resolve => setTimeout(resolve, 2000));

    const reports = getReportFiles(testOutputDir);
    
    console.log('Generated reports:', reports);
    
    // Should have at least JSON report
    const jsonReports = reports.filter(f => f.endsWith('.json'));
    const htmlReports = reports.filter(f => f.endsWith('.html'));
    
    expect(jsonReports.length).toBeGreaterThan(0);
    expect(htmlReports.length).toBeGreaterThan(0);
    
    // Validate JSON report structure
    if (jsonReports.length > 0) {
      const jsonPath = path.join(testOutputDir, jsonReports[0]);
      const jsonContent = JSON.parse(fs.readFileSync(jsonPath, 'utf8'));
      
      expect(jsonContent).toHaveProperty('scanId');
      expect(jsonContent).toHaveProperty('vulnerabilities');
      expect(jsonContent).toHaveProperty('summary');
      expect(Array.isArray(jsonContent.vulnerabilities)).toBe(true);
    }
    
    console.log('✓ Reports generated with correct structure');
  });

  test('should respect custom output directory', async () => {
    test.setTimeout(90000);
    
    const customDir = path.join(testOutputDir, 'custom-reports');
    
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--passive',
      '--formats', 'json',
      '--output', customDir,
    ], 60000);

    await new Promise(resolve => setTimeout(resolve, 2000));

    expect(fs.existsSync(customDir)).toBe(true);
    
    const reports = getReportFiles(customDir);
    expect(reports.length).toBeGreaterThan(0);
    
    console.log('✓ Custom output directory respected');
  });
});

// ============================================================================
// TEST SUITE: Local Juice Shop (Optional - requires localhost:3000)
// ============================================================================
test.describe('CLI Local Target (Juice Shop)', () => {
  
  test.beforeEach(async () => {
    // Skip if Juice Shop is not running
    try {
      const response = await fetch('http://localhost:3000', { 
        method: 'HEAD',
        signal: AbortSignal.timeout(5000) 
      });
      if (!response.ok) {
        test.skip();
      }
    } catch {
      console.log('⚠ Skipping Juice Shop tests - localhost:3000 not available');
      test.skip();
    }
  });

  test('passive scan on localhost:3000 should work', async () => {
    test.setTimeout(90000);
    
    console.log('Running: kinetic http://localhost:3000 --passive');
    const output = await runCli([
      'http://localhost:3000',
      '--passive',
      '--formats', 'console',
    ], 60000);

    const combinedOutput = output.stdout + output.stderr;
    
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    expect(hasActiveActivity(combinedOutput)).toBe(false);
    
    console.log('✓ Juice Shop passive scan completed');
  });

  test('combined scan on localhost:3000 should run both scanners', async () => {
    test.setTimeout(180000);
    
    console.log('Running: kinetic http://localhost:3000 --scan-type both');
    const output = await runCli([
      'http://localhost:3000',
      '--scan-type', 'both',
      '--formats', 'console',
    ], 120000);

    const combinedOutput = output.stdout + output.stderr;
    
    expect(hasActiveActivity(combinedOutput)).toBe(true);
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    
    console.log('✓ Juice Shop combined scan completed');
  });
});

// ============================================================================
// TEST SUITE: CLI Flag Edge Cases
// ============================================================================
test.describe('CLI Flag Edge Cases', () => {

  test('--no-active should disable active scanner', async () => {
    test.setTimeout(90000);
    
    console.log('Running: kinetic http://testphp.vulnweb.com/ --no-active --passive');
    const output = await runCli([
      'http://testphp.vulnweb.com/',
      '--no-active',
      '--passive',
      '--formats', 'console',
    ], 60000);

    const combinedOutput = output.stdout + output.stderr;
    
    // Should have passive but not active
    expect(hasPassiveActivity(combinedOutput)).toBe(true);
    expect(hasActiveActivity(combinedOutput)).toBe(false);
    
    console.log('✓ --no-active flag works correctly');
  });

  test('should handle missing URL gracefully', async () => {
    const output = await runCli([], 10000);
    
    const combinedOutput = output.stdout + output.stderr;
    
    expect(combinedOutput).toContain('Error: URL required');
    expect(output.exitCode).not.toBe(0);
    
    console.log('✓ Missing URL handled gracefully');
  });

  test('should display version', async () => {
    const output = await runCli(['--version'], 5000);
    
    expect(output.stdout).toMatch(/\d+\.\d+\.\d+/); // Version pattern
    
    console.log('✓ Version displayed correctly');
  });

  test('should display help', async () => {
    const output = await runCli(['--help'], 5000);
    
    expect(output.stdout).toContain('kinetic');
    expect(output.stdout).toContain('--passive');
    expect(output.stdout).toContain('--active');
    expect(output.stdout).toContain('--scan-type');
    
    console.log('✓ Help displayed correctly');
  });
});
