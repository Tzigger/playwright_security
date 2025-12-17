import { ScanEngine } from '@core/engine/ScanEngine';
import { ScannerType, LogLevel, BrowserType } from '@types/enums';
import { IScanner } from '@core/interfaces/IScanner';

// Mock Scanner to avoid actual network traffic/scanning
class MockScanner implements IScanner {
  type = ScannerType.ACTIVE;
  async initialize() {}
  async execute() {}
  async cleanup() {}
  isEnabled() { return true; }
}

describe('Auto Safe Mode Integration', () => {
  let engine: ScanEngine;

  beforeEach(() => {
    engine = new ScanEngine();
    engine.registerScanner(new MockScanner());
  });

  it('should automatically enable safe mode for non-local targets', async () => {
    const config = {
      target: { url: 'http://example.com' }, // Non-local
      scanners: {
        active: {
          enabled: true,
          // safeMode is undefined
        },
      },
      browser: { 
        type: BrowserType.CHROMIUM,
        headless: true 
      }
    };

    await engine.loadConfiguration(config as any);

    return new Promise<void>((resolve, reject) => {
      engine.on('scanStarted', ({ config }) => {
        try {
          expect(config.scanners.active.safeMode).toBe(true);
          // Stop the scan immediately as we just wanted to check config
          engine.stop().then(() => resolve());
        } catch (e) {
          reject(e);
        }
      });

      engine.scan().catch(() => {
        // expected to fail/stop
      });
    });
  });

  it('should NOT enable safe mode for local targets', async () => {
    const config = {
      target: { url: 'http://localhost:8080' }, // Local
      scanners: {
        active: {
          enabled: true,
          // safeMode is undefined
        },
      },
      browser: { 
        type: BrowserType.CHROMIUM,
        headless: true 
      }
    };

    await engine.loadConfiguration(config as any);

    return new Promise<void>((resolve, reject) => {
      engine.on('scanStarted', ({ config }) => {
        try {
          expect(config.scanners.active.safeMode).toBeUndefined(); 
          
          engine.stop().then(() => resolve());
        } catch (e) {
          reject(e);
        }
      });

      engine.scan().catch(() => {});
    });
  });
  
  it('should respect explicit safeMode=false even on non-local targets', async () => {
    const config = {
      target: { url: 'http://example.com' },
      scanners: {
        active: {
          enabled: true,
          safeMode: false, // Explicitly disabled
        },
      },
      browser: { 
        type: BrowserType.CHROMIUM,
        headless: true 
      }
    };

    await engine.loadConfiguration(config as any);

    return new Promise<void>((resolve, reject) => {
      engine.on('scanStarted', ({ config }) => {
        try {
          expect(config.scanners.active.safeMode).toBe(false);
          engine.stop().then(() => resolve());
        } catch (e) {
          reject(e);
        }
      });

      engine.scan().catch(() => {});
    });
  });
});
