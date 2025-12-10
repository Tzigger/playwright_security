import { chromium } from 'playwright';
import fs from 'fs';

(async () => {
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  try {
    console.log('Navigating to target...');
    await page.goto('https://beta-squad-fe-production.up.railway.app/', { waitUntil: 'domcontentloaded' });
    console.log('Waiting 10s for potential animations/redirects...');
    await page.waitForTimeout(10000);
    
    console.log('Page Title:', await page.title());
    
    // Screenshot
    await page.screenshot({ path: 'beta-squad-screenshot.png', fullPage: true });
    console.log('Screenshot saved to beta-squad-screenshot.png');

    // HTML
    const html = await page.content();
    fs.writeFileSync('beta-squad-dump.html', html);
    console.log('HTML saved to beta-squad-dump.html');

    // Quick check for inputs
    const inputs = await page.locator('input, textarea, button, select').count();
    console.log(`Found ${inputs} interactive elements (input, textarea, button, select)`);

  } catch (e) {
    console.error('Error:', e);
  } finally {
    await browser.close();
  }
})();
