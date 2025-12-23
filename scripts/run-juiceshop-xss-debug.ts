import { ScanEngine } from '../src/core/engine/ScanEngine';
import { ActiveScanner } from '../src/scanners/active/ActiveScanner';
import { registerBuiltInDetectors } from '../src/utils/builtInDetectors';
import { DetectorRegistry } from '../src/utils/DetectorRegistry';
import { Logger } from '../src/utils/logger/Logger';
import { LogLevel } from '../src/types/enums';
import * as path from 'path';

async function main() {
  const logger = new Logger(LogLevel.INFO, 'JuiceShopScan');
  
  try {
    // 1. Initialize Engine
    const engine = new ScanEngine();
    
    // 2. Load Configuration
    const configPath = path.join(process.cwd(), 'config', 'juiceshop-xss-debug.config.json');
    await engine.loadConfigurationFromFile(configPath);
    
    // 3. Register Detectors
    registerBuiltInDetectors();
    const registry = DetectorRegistry.getInstance();
    
    // 4. Register Scanners & Wire Detectors
    // Only Active Scanner for this debug run
    const activeScanner = new ActiveScanner();
    const activeDetectors = registry.getActiveDetectors();
    activeScanner.registerDetectors(activeDetectors);
    engine.registerScanner(activeScanner);
    
    // 5. Run Scan
    logger.info('Starting XSS debug scan...');
    const result = await engine.scan();
    
    logger.info('Scan complete!');
    logger.info(`Total vulnerabilities: ${result.summary.total}`);
    logger.info(`Critical: ${result.summary.critical}`);
    logger.info(`High: ${result.summary.high}`);
    logger.info(`Medium: ${result.summary.medium}`);
    logger.info(`Low: ${result.summary.low}`);
    
    // 6. Cleanup
    await engine.cleanup();
    
  } catch (error) {
    logger.error(`Scan failed: ${error}`);
    process.exit(1);
  }
}

main().catch(console.error);
