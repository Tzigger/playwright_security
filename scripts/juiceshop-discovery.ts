import { chromium } from 'playwright';
import { DomExplorer, AttackSurfaceType } from '../src/scanners/active/DomExplorer';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import * as fs from 'fs';
import * as path from 'path';

async function main() {
  const logger = new Logger(LogLevel.INFO, 'JuiceShopDiscovery');
  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();

  const targetUrl = process.env['JUICESHOP_URL'] || 'http://localhost:3000';
  logger.info(`Navigating to ${targetUrl}`);
  
  const explorer = new DomExplorer(LogLevel.DEBUG);
  const collectedRequests: any[] = [];
  page.on('request', (req) => collectedRequests.push(req));
  explorer.startMonitoring(page);

  try {
    await page.goto(targetUrl);
    await page.waitForLoadState('networkidle');
    
    // Wait a bit for SPA to settle
    await page.waitForTimeout(5000);

    const surfaces = await explorer.explore(page, collectedRequests);
    
    // Filter for API surfaces and high value params
    const candidates = surfaces.filter(s => {
      if (s.type === AttackSurfaceType.API_PARAM || s.type === AttackSurfaceType.JSON_BODY) return true;
      if (s.metadata?.url?.includes('/rest/')) return true;
      if (['q', 'id', 'email', 'search', 'query'].includes(s.name.toLowerCase())) return true;
      return false;
    });

    logger.info(`Found ${candidates.length} candidates out of ${surfaces.length} surfaces`);

    const outputPath = path.join(process.cwd(), 'test-security-reports', 'juiceshop-candidates.json');
    fs.mkdirSync(path.dirname(outputPath), { recursive: true });
    fs.writeFileSync(outputPath, JSON.stringify(candidates, null, 2));
    logger.info(`Saved candidates to ${outputPath}`);
  } catch (error) {
    logger.error(`Discovery failed: ${error}`);
  } finally {
    await browser.close();
  }
}

main().catch(console.error);
