import { test, expect } from '@playwright/test';
import { SqlInjectionDetector } from '../../src/detectors/active/SqlInjectionDetector';
import { XssDetector } from '../../src/detectors/active/XssDetector';

test.describe('Detector Configuration - Permissive Mode', () => {
  test('SqlInjectionDetector lowers minConfidenceForEarlyExit in permissive mode when not specified', () => {
    const detector = new SqlInjectionDetector({ permissiveMode: true });
    // @ts-ignore - accessing private/protected config for testing purposes
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.6);
  });

  test('SqlInjectionDetector keeps default minConfidenceForEarlyExit in strict mode', () => {
    const detector = new SqlInjectionDetector({ permissiveMode: false });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.9);
  });

  test('SqlInjectionDetector respects explicit minConfidenceForEarlyExit in permissive mode', () => {
    const detector = new SqlInjectionDetector({ permissiveMode: true, minConfidenceForEarlyExit: 0.8 });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.8);
  });
  
  test('SqlInjectionDetector respects explicit lower minConfidenceForEarlyExit in permissive mode', () => {
    const detector = new SqlInjectionDetector({ permissiveMode: true, minConfidenceForEarlyExit: 0.5 });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.5);
  });

  test('XssDetector lowers minConfidenceForEarlyExit in permissive mode when not specified', () => {
    const detector = new XssDetector({ permissiveMode: true });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.6);
  });

  test('XssDetector keeps default minConfidenceForEarlyExit in strict mode', () => {
    const detector = new XssDetector({ permissiveMode: false });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.9);
  });

  test('XssDetector respects explicit minConfidenceForEarlyExit in permissive mode', () => {
    const detector = new XssDetector({ permissiveMode: true, minConfidenceForEarlyExit: 0.8 });
    // @ts-ignore
    expect(detector.config.minConfidenceForEarlyExit).toBe(0.8);
  });
});
