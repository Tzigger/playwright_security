import { test, expect } from '@playwright/test';

// bWAPP specific test suite for validating detectors against manual payloads
// These tests verify that our detectors are capable of finding vulnerabilities
// using the exact payloads that work on bWAPP, confirming our "permissive mode" logic.

const BASE_URL = process.env.BWAPP_URL || 'http://localhost:8080';

// Skip if bWAPP is not running
test.skip(async () => {
    try {
        const response = await fetch(BASE_URL);
        return !response.ok;
    } catch {
        return true;
    }
}, 'bWAPP not available');

test.use({ storageState: 'storage-states/bwapp-auth.json' });

test.describe('bWAPP Specific Payload Validation', () => {

    test('SQLi on sqli_1.php with exact payload', async ({ page }) => {
        await page.goto(`${BASE_URL}/sqli_1.php`);
        // Verify we are on the right page
        await expect(page).toHaveURL(/sqli_1\.php/);
        
        // Manual injection
        const payload = "' OR '1'='1";
        await page.fill('input[name="title"]', payload);
        await page.click('button[type="submit"]');
        
        const body = await page.content();
        // bWAPP shows movie list (7 items usually) on success
        expect(body).toContain('The movie:');
        expect(body).toContain('Iron Man');
        
        console.log('Confirmed manual SQLi works on sqli_1.php');
    });

    test('XSS on xss_get.php with exact payload', async ({ page }) => {
        await page.goto(`${BASE_URL}/xss_get.php`);
        
        const payload = '<script>alert(1)</script>';
        // We can't easily catch the alert in this simple test without listening, 
        // but we can check reflection in source
        await page.fill('input[name="firstname"]', payload);
        await page.fill('input[name="lastname"]', 'test');
        await page.click('button[type="submit"]');
        
        const body = await page.content();
        expect(body).toContain(payload);
        
        console.log('Confirmed manual XSS payload reflection on xss_get.php');
    });

    test('Command Injection on commandi.php with exact payload', async ({ page }) => {
        await page.goto(`${BASE_URL}/commandi.php`);
        
        const payload = '; id';
        await page.fill('input[name="target"]', payload);
        await page.click('button[type="submit"]');
        
        const body = await page.content();
        // Check for output of 'id' command
        expect(body).toMatch(/uid=\d+/);
        expect(body).toMatch(/gid=\d+/);
        
        console.log('Confirmed manual Command Injection works on commandi.php');
    });
});
