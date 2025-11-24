/**
 * Example: Using Playwright Security Framework in Playwright Tests
 * 
 * This shows how to integrate security scanning into your E2E tests.
 */
import { test, expect } from '@playwright/test';
import { runSecurityScan, assertNoVulnerabilities, VulnerabilitySeverity } from '../src/testing/helpers';

test.describe('Security Testing Examples', () => {
  
  test('should scan login page for vulnerabilities', async ({ page }) => {
    // Navigate to your app
    await page.goto('https://example.com/login');
    
    // Run security scan
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'all',
      maxPages: 1,
    });
    
    // Assert no critical vulnerabilities
    const critical = vulnerabilities.filter(v => v.severity === VulnerabilitySeverity.CRITICAL);
    expect(critical).toHaveLength(0);
    
    // Log findings for review
    if (vulnerabilities.length > 0) {
      console.log('⚠️  Vulnerabilities found:', vulnerabilities.map(v => 
        `${v.severity}: ${v.title}`
      ));
    }
  });

  test('should allow only low severity issues in staging', async ({ page }) => {
    await page.goto('https://staging.example.com');
    
    const vulnerabilities = await runSecurityScan(page.url());
    
    // Fail if anything above LOW severity found
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.LOW);
  });

  test('should scan search functionality for SQL injection', async ({ page }) => {
    await page.goto('https://example.com/search');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      detectors: 'sql', // Only SQL injection tests
      maxPages: 1,
    });
    
    expect(vulnerabilities).toHaveLength(0);
  });

  test('production must have zero vulnerabilities', async ({ page }) => {
    await page.goto('https://example.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 5,
    });
    
    // Production: no exceptions
    assertNoVulnerabilities(vulnerabilities, VulnerabilitySeverity.INFO);
  });

  test.skip('manual security review', async ({ page }) => {
    // Use this to generate security report for manual review
    await page.goto('https://example.com');
    
    const vulnerabilities = await runSecurityScan(page.url(), {
      maxPages: 10,
    });
    
    console.log('📊 Security Scan Results:');
    console.log(`Total vulnerabilities: ${vulnerabilities.length}`);
    console.log(JSON.stringify(vulnerabilities, null, 2));
  });
});
