/**
 * Juice Shop Enhanced Scan Example
 * 
 * This example demonstrates the enhanced DAST framework capabilities:
 * - API endpoint auto-discovery
 * - Response analysis for SQL errors and XSS reflection
 * - SPA-aware content waiting
 * - Direct API security testing
 * 
 * Run with: npx ts-node examples/juice-shop-enhanced-scan.ts
 */

import { chromium, Page } from 'playwright';
import { ApiEndpointDiscovery, ApiEndpoint } from '../src/scanners/active/ApiEndpointDiscovery';
import { ApiScanner } from '../src/scanners/active/ApiScanner';
import { ResponseAnalyzer } from '../src/core/analysis/ResponseAnalyzer';
import { LogLevel } from '../src/types/enums';
import { Vulnerability } from '../src/types/vulnerability';

const TARGET_URL = 'http://localhost:3000';

async function runEnhancedScan() {
  console.log('🔍 Starting Enhanced Juice Shop Security Scan');
  console.log('='.repeat(60));
  
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  // Initialize enhanced components
  const apiDiscovery = new ApiEndpointDiscovery({}, LogLevel.INFO);
  const responseAnalyzer = new ResponseAnalyzer({ enabled: true });
  const apiScanner = new ApiScanner({});

  // Track findings
  const allVulnerabilities: Vulnerability[] = [];
  const discoveredApis: ApiEndpoint[] = [];

  try {
    // Phase 1: Navigate and discover APIs
    console.log('\n📡 Phase 1: API Discovery');
    console.log('-'.repeat(40));
    
    await apiDiscovery.startDiscovery(page);
    
    // Navigate to main pages to discover API endpoints
    const pagesToVisit = [
      TARGET_URL,
      `${TARGET_URL}/#/login`,
      `${TARGET_URL}/#/register`,
      `${TARGET_URL}/#/search`,
      `${TARGET_URL}/#/basket`,
      `${TARGET_URL}/#/contact`,
    ];

    for (const url of pagesToVisit) {
      console.log(`  Visiting: ${url}`);
      try {
        await page.goto(url, { waitUntil: 'networkidle', timeout: 15000 });
        await page.waitForTimeout(2000); // Let SPA settle
      } catch (e) {
        console.log(`  ⚠️ Timeout on ${url}, continuing...`);
      }
    }

    // Interact with search to trigger API calls
    try {
      await page.goto(`${TARGET_URL}/#/search`, { waitUntil: 'networkidle', timeout: 10000 });
      const searchInput = page.locator('input[type="text"], input[placeholder*="search" i], mat-form-field input').first();
      if (await searchInput.isVisible()) {
        await searchInput.fill('test');
        await page.keyboard.press('Enter');
        await page.waitForTimeout(2000);
      }
    } catch (e) {
      console.log('  Search interaction failed, continuing...');
    }

    // Stop discovery and get results
    apiDiscovery.stopDiscovery();
    const endpoints = apiDiscovery.getEndpoints();
    discoveredApis.push(...endpoints);
    
    console.log(`\n✅ Discovered ${endpoints.length} API endpoints:`);
    for (const ep of endpoints.slice(0, 10)) {
      console.log(`  ${ep.method} ${ep.path}`);
    }
    if (endpoints.length > 10) {
      console.log(`  ... and ${endpoints.length - 10} more`);
    }

    // Phase 2: Direct API Security Testing
    console.log('\n⚡ Phase 2: Direct API Security Testing');
    console.log('-'.repeat(40));

    if (endpoints.length > 0) {
      console.log(`  Testing ${Math.min(endpoints.length, 20)} API endpoints...`);
      
      await apiScanner.initialize(context);
      const apiResults = await apiScanner.scanEndpoints(endpoints.slice(0, 20));
      allVulnerabilities.push(...apiResults);
      
      console.log(`\n✅ API scan found ${apiResults.length} vulnerabilities`);
    }

    // Phase 3: Targeted Vulnerability Tests
    console.log('\n🎯 Phase 3: Targeted Vulnerability Tests');
    console.log('-'.repeat(40));

    // Test login for SQL injection
    console.log('  Testing login form for SQL injection...');
    const loginVulns = await testLoginSQLInjection(page, responseAnalyzer);
    allVulnerabilities.push(...loginVulns);

    // Test search for XSS
    console.log('  Testing search for XSS...');
    const xssVulns = await testSearchXSS(page);
    allVulnerabilities.push(...xssVulns);

    // Results Summary
    console.log('\n' + '='.repeat(60));
    console.log('📊 SCAN RESULTS SUMMARY');
    console.log('='.repeat(60));
    
    console.log(`\n📡 API Endpoints Discovered: ${discoveredApis.length}`);
    console.log(`🔴 Total Vulnerabilities Found: ${allVulnerabilities.length}`);
    
    // Group by severity
    const bySeverity: Record<string, number> = {};
    for (const vuln of allVulnerabilities) {
      const sev = String(vuln.severity || 'unknown').toLowerCase();
      bySeverity[sev] = (bySeverity[sev] || 0) + 1;
    }
    
    console.log('\nBy Severity:');
    for (const [severity, count] of Object.entries(bySeverity).sort()) {
      const emoji = severity === 'critical' ? '🔴' : severity === 'high' ? '🟠' : severity === 'medium' ? '🟡' : '🟢';
      console.log(`  ${emoji} ${severity}: ${count}`);
    }

    // Group by category
    const byCategory: Record<string, number> = {};
    for (const vuln of allVulnerabilities) {
      const cat = String(vuln.category || 'unknown');
      byCategory[cat] = (byCategory[cat] || 0) + 1;
    }
    
    console.log('\nBy Category:');
    for (const [category, count] of Object.entries(byCategory).sort((a, b) => b[1] - a[1])) {
      console.log(`  ${category}: ${count}`);
    }

    // List vulnerabilities
    if (allVulnerabilities.length > 0) {
      console.log('\n📋 Vulnerability Details:');
      for (const vuln of allVulnerabilities.slice(0, 20)) {
        console.log(`\n  [${String(vuln.severity || 'unknown').toUpperCase()}] ${vuln.title}`);
        console.log(`    URL: ${vuln.url || 'N/A'}`);
        console.log(`    Category: ${vuln.category}`);
        console.log(`    Description: ${(vuln.description || '').substring(0, 100)}`);
      }
      if (allVulnerabilities.length > 20) {
        console.log(`\n  ... and ${allVulnerabilities.length - 20} more vulnerabilities`);
      }
    }

  } catch (error) {
    console.error('Scan error:', error);
  } finally {
    await browser.close();
  }

  console.log('\n✅ Enhanced scan complete!');
}

async function testLoginSQLInjection(page: Page, responseAnalyzer: ResponseAnalyzer): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  
  await page.goto(`${TARGET_URL}/#/login`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);
  
  const sqlPayloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "admin'--",
    "' UNION SELECT NULL,NULL,NULL--",
    "1; DROP TABLE users--",
  ];

  for (const payload of sqlPayloads) {
    try {
      const emailInput = page.locator('#email, input[name="email"], input[type="email"]').first();
      const passwordInput = page.locator('#password, input[name="password"], input[type="password"]').first();
      
      if (await emailInput.isVisible({ timeout: 3000 }) && await passwordInput.isVisible({ timeout: 3000 })) {
        await emailInput.fill(payload);
        await passwordInput.fill('test123');
        
        // Monitor response
        const responsePromise = page.waitForResponse(
          resp => resp.url().includes('/rest') || resp.url().includes('/api'),
          { timeout: 5000 }
        ).catch(() => null);
        
        await page.locator('button[type="submit"], button:has-text("Log in")').first().click();
        
        const response = await responsePromise;
        if (response) {
          const responseText = await response.text().catch(() => '');
          
          // Analyze response for vulnerabilities
          const responseVulns = responseAnalyzer.analyzeText(responseText, response.url());
          if (responseVulns.length > 0) {
            console.log(`  🔴 SQL Injection detected with payload: ${payload.substring(0, 30)}`);
            // Create vulnerability record
            for (const rv of responseVulns) {
              vulnerabilities.push({
                id: `sqli-login-${Date.now()}`,
                category: 'injection' as any,
                title: `SQL Injection - ${rv.type}`,
                description: rv.context,
                severity: rv.severity,
                url: response.url(),
                evidence: {
                  source: rv.indicator,
                  requestBody: payload,
                },
                remediation: 'Use parameterized queries and input validation',
                references: ['https://owasp.org/Top10/A03_2021-Injection/'],
                timestamp: new Date(),
              });
            }
          }
        }
        
        // Reset form
        await page.goto(`${TARGET_URL}/#/login`, { waitUntil: 'networkidle', timeout: 10000 });
        await page.waitForTimeout(1000);
      }
    } catch (e) {
      // Continue with next payload
    }
  }
  
  return vulnerabilities;
}

async function testSearchXSS(page: Page): Promise<Vulnerability[]> {
  const vulnerabilities: Vulnerability[] = [];
  
  await page.goto(`${TARGET_URL}/#/search`, { waitUntil: 'networkidle', timeout: 15000 });
  await page.waitForTimeout(2000);

  const xssPayloads = [
    '<script>alert("XSS")</script>',
    '<img src=x onerror=alert("XSS")>',
    '"><script>alert("XSS")</script>',
    "'-alert('XSS')-'",
  ];

  for (const payload of xssPayloads) {
    try {
      const searchInput = page.locator('input[type="text"], input[placeholder*="search" i], mat-form-field input').first();
      if (await searchInput.isVisible({ timeout: 3000 })) {
        await searchInput.fill(payload);
        await page.keyboard.press('Enter');
        await page.waitForTimeout(2000);
        
        // Check if payload is reflected in page
        const content = await page.content();
        if (content.includes(payload) && !content.includes(encodeURIComponent(payload).replace(/%20/g, '+'))) {
          console.log(`  🔴 Potential XSS detected with payload: ${payload.substring(0, 30)}`);
          vulnerabilities.push({
            id: `xss-search-${Date.now()}`,
            category: 'xss' as any,
            title: 'Reflected XSS in Search',
            description: `Payload reflected without encoding: ${payload}`,
            severity: 'high' as any,
            url: page.url(),
            evidence: {
              source: 'search input',
              requestBody: payload,
            },
            remediation: 'Encode user input before rendering',
            references: ['https://owasp.org/Top10/A03_2021-Injection/'],
            timestamp: new Date(),
          });
        }
        
        // Reset
        await page.goto(`${TARGET_URL}/#/search`, { waitUntil: 'networkidle', timeout: 10000 });
        await page.waitForTimeout(1000);
      }
    } catch (e) {
      // Continue with next payload
    }
  }
  
  return vulnerabilities;
}

runEnhancedScan().catch(console.error);
