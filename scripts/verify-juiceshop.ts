import { chromium } from 'playwright';
import * as fs from 'fs';
import * as path from 'path';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import { PayloadInjector, InjectionStrategy, PayloadEncoding } from '../src/scanners/active/PayloadInjector';
import { AttackSurface } from '../src/scanners/active/DomExplorer';

async function main() {
  const logger = new Logger(LogLevel.INFO, 'VerifyJuiceShop');
  const candidatesPath = path.join(process.cwd(), 'test-security-reports', 'juiceshop-candidates.json');
  
  if (!fs.existsSync(candidatesPath)) {
    logger.error(`Candidates file not found: ${candidatesPath}`);
    return;
  }

  const candidates: AttackSurface[] = JSON.parse(fs.readFileSync(candidatesPath, 'utf-8'));
  logger.info(`Loaded ${candidates.length} candidates`);

  const browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const injector = new PayloadInjector(LogLevel.DEBUG);

  const results: any[] = [];

  for (const surface of candidates) {
    logger.info(`Verifying surface: ${surface.name} (${surface.type})`);
    
    // Test payloads
    const payloads = [
      '<script>alert(1)</script>',
      "' OR '1'='1",
      '{{7*7}}'
    ];

    for (const payload of payloads) {
      try {
        // Navigate to base URL first to ensure clean state
        await page.goto(surface.metadata.url || 'http://localhost:3000');
        await page.waitForLoadState('networkidle');

        const result = await injector.inject(page, surface, payload, {
          strategy: InjectionStrategy.REPLACE,
          encoding: PayloadEncoding.NONE
        });

        results.push({
          surface: surface.name,
          type: surface.type,
          payload,
          result: result.response ? result.response.status : 'no-response',
          error: result.error
        });
        
        logger.info(`  Payload: ${payload} -> Status: ${result.response?.status}`);
      } catch (error) {
        logger.error(`  Failed to inject ${payload}: ${error}`);
        results.push({
          surface: surface.name,
          type: surface.type,
          payload,
          error: String(error)
        });
      }
    }
  }

  const outputPath = path.join(process.cwd(), 'test-security-reports', 'juiceshop-verification.json');
  fs.writeFileSync(outputPath, JSON.stringify(results, null, 2));
  logger.info(`Saved verification results to ${outputPath}`);

  await browser.close();
}

main().catch(console.error);
