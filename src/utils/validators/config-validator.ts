import { ScanConfiguration } from '../../types/config';

/**
 * Validate scan configuration
 */
export function validateScanConfiguration(config: Partial<ScanConfiguration>): {
  valid: boolean;
  errors: string[];
} {
  const errors: string[] = [];

  // Validate target
  if (!config.target?.url) {
    errors.push('Target URL is required');
  } else if (!isValidUrl(config.target.url)) {
    errors.push('Target URL is invalid');
  }

  // Validate browser config
  if (config.browser) {
    if (!['chromium', 'firefox', 'webkit'].includes(config.browser.type)) {
      errors.push('Invalid browser type');
    }
  }

  // Validate reporting config
  if (config.reporting) {
    if (!config.reporting.outputDir) {
      errors.push('Output directory is required');
    }
    if (config.reporting.formats.length === 0) {
      errors.push('At least one report format must be specified');
    }
  }

  // Validate advanced config
  if (config.advanced) {
    if (config.advanced.parallelism && config.advanced.parallelism < 1) {
      errors.push('Parallelism must be at least 1');
    }
    if (config.advanced.maxRetries && config.advanced.maxRetries < 0) {
      errors.push('Max retries cannot be negative');
    }
  }

  return {
    valid: errors.length === 0,
    errors,
  };
}

/**
 * Validate URL format
 */
export function isValidUrl(url: string): boolean {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol);
  } catch {
    return false;
  }
}

/**
 * Validate regex pattern
 */
export function isValidRegex(pattern: string): boolean {
  try {
    new RegExp(pattern);
    return true;
  } catch {
    return false;
  }
}

/**
 * Validate file path
 */
export function isValidPath(path: string): boolean {
  // Basic validation - check for null bytes and invalid characters
  if (path.includes('\0')) return false;
  if (path.trim().length === 0) return false;
  return true;
}

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

/**
 * Validate port number
 */
export function isValidPort(port: number): boolean {
  return Number.isInteger(port) && port >= 1 && port <= 65535;
}

/**
 * Validate confidence score (0-1)
 */
export function isValidConfidence(confidence: number): boolean {
  return typeof confidence === 'number' && confidence >= 0 && confidence <= 1;
}
