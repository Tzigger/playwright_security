import { TargetValidator } from '@utils/TargetValidator';

describe('TargetValidator', () => {
  let validator: TargetValidator;

  beforeEach(() => {
    validator = new TargetValidator();
  });

  describe('Local Environment Detection', () => {
    it('should detect localhost as local', () => {
      const result = validator.validateUrl('http://localhost:3000');
      expect(result.isLocal).toBe(true);
      expect(result.environment).toBe('local');
    });

    it('should detect 127.0.0.1 as local', () => {
      const result = validator.validateUrl('http://127.0.0.1:3000');
      expect(result.isLocal).toBe(true);
      expect(result.environment).toBe('local');
    });

    it('should detect private IP 192.168.x.x as local', () => {
      const result = validator.validateUrl('http://192.168.1.1:3000');
      expect(result.isLocal).toBe(true);
      expect(result.environment).toBe('local');
    });

    it('should detect private IP 10.x.x.x as local', () => {
      const result = validator.validateUrl('http://10.0.0.1:3000');
      expect(result.isLocal).toBe(true);
      expect(result.environment).toBe('local');
    });

    it('should not warn for HTTP on local targets', () => {
      const result = validator.validateUrl('http://localhost:3000');
      const hasHTTPWarning = result.warnings.some(w => w.includes('HTTPS') || w.includes('HTTP'));
      expect(hasHTTPWarning).toBe(false);
    });

    it('should not warn about development ports on local targets', () => {
      const result = validator.validateUrl('http://localhost:3000');
      const hasPortWarning = result.warnings.some(w => w.includes('3000'));
      expect(hasPortWarning).toBe(false);
    });
  });

  describe('Staging Environment Detection', () => {
    it('should detect .staging domains as staging', () => {
      const result = validator.validateUrl('https://app.staging.example.com');
      expect(result.environment).toBe('staging');
      expect(result.isLocal).toBe(false);
      expect(result.isProduction).toBe(false);
    });

    it('should detect .stage domains as staging', () => {
      const result = validator.validateUrl('https://api.stage.example.com');
      expect(result.environment).toBe('staging');
    });

    it('should detect .test domains as staging', () => {
      const result = validator.validateUrl('https://app.test.example.com');
      expect(result.environment).toBe('staging');
    });

    it('should detect .qa domains as staging', () => {
      const result = validator.validateUrl('https://app.qa.example.com');
      expect(result.environment).toBe('staging');
    });

    it('should detect .dev domains as staging', () => {
      const result = validator.validateUrl('https://app.dev.example.com');
      expect(result.environment).toBe('staging');
    });

    it('should warn about non-local targets', () => {
      const result = validator.validateUrl('https://app.staging.example.com');
      const hasWarning = result.warnings.some(w => w.includes('staging'));
      expect(hasWarning).toBe(true);
    });

    it('should recommend safe mode for non-local targets', () => {
      const result = validator.validateUrl('https://app.staging.example.com');
      const hasSafeModeRecommendation = result.recommendations.some(r => r.includes('safe mode'));
      expect(hasSafeModeRecommendation).toBe(true);
    });
  });

  describe('Production Environment Detection', () => {
    it('should detect .prod domains as production', () => {
      const result = validator.validateUrl('https://app.prod.example.com');
      expect(result.isProduction).toBe(true);
      expect(result.environment).toBe('production');
    });

    it('should detect .production domains as production', () => {
      const result = validator.validateUrl('https://app.production.example.com');
      expect(result.isProduction).toBe(true);
    });

    it('should detect plain domain names as production', () => {
      const result = validator.validateUrl('https://example.com');
      expect(result.isProduction).toBe(true);
      expect(result.environment).toBe('production');
    });

    it('should detect public IPs as production', () => {
      const result = validator.validateUrl('https://8.8.8.8');
      expect(result.isProduction).toBe(true);
    });

    it('should warn about HTTP on production', () => {
      const result = validator.validateUrl('http://example.com');
      const hasHTTPWarning = result.warnings.some(w => w.toUpperCase().includes('HTTPS'));
      expect(hasHTTPWarning).toBe(true);
    });

    it('should recommend HTTPS for production', () => {
      const result = validator.validateUrl('http://example.com');
      const hasHTTPSRecommendation = result.recommendations.some(r => r.toUpperCase().includes('HTTPS'));
      expect(hasHTTPSRecommendation).toBe(true);
    });

    it('should warn about development ports on production', () => {
      const result = validator.validateUrl('https://example.com:3000');
      const hasPortWarning = result.warnings.some(w => w.includes('3000'));
      expect(hasPortWarning).toBe(true);
    });
  });

  describe('URL Validation', () => {
    it('should validate well-formed URLs', () => {
      const result = validator.validateUrl('https://example.com');
      expect(result.isValid).toBe(true);
    });

    it('should reject invalid URLs', () => {
      const result = validator.validateUrl('not a valid url');
      expect(result.isValid).toBe(false);
    });

    it('should reject URLs without protocol', () => {
      const result = validator.validateUrl('example.com');
      expect(result.isValid).toBe(false);
    });

    it('should handle URLs with paths', () => {
      const result = validator.validateUrl('https://example.com/api/users');
      expect(result.isValid).toBe(true);
    });

    it('should handle URLs with query parameters', () => {
      const result = validator.validateUrl('https://example.com?param=value');
      expect(result.isValid).toBe(true);
    });

    it('should handle URLs with fragments', () => {
      const result = validator.validateUrl('https://example.com#section');
      expect(result.isValid).toBe(true);
    });
  });

  describe('shouldBlockActiveScan()', () => {
    it('should allow active scan on localhost', () => {
      const result = validator.shouldBlockActiveScan('http://localhost:3000');
      expect(result.shouldBlock).toBe(false);
    });

    it('should allow active scan on staging', () => {
      const result = validator.shouldBlockActiveScan('https://app.staging.example.com');
      expect(result.shouldBlock).toBe(false);
    });

    it('should block active scan on production by default', () => {
      const result = validator.shouldBlockActiveScan('https://example.com');
      expect(result.shouldBlock).toBe(true);
    });

    it('should allow production scans with confirmProduction flag', () => {
      const result = validator.shouldBlockActiveScan('https://example.com', {
        confirmProduction: true,
      });
      expect(result.shouldBlock).toBe(false);
    });

    it('should reject invalid URLs', () => {
      const result = validator.shouldBlockActiveScan('not a url');
      expect(result.shouldBlock).toBe(true);
    });

    it('should provide reason for blocking', () => {
      const result = validator.shouldBlockActiveScan('https://example.com');
      expect(result.reason).toContain('production');
    });
  });

  describe('getSummary()', () => {
    it('should return formatted summary for localhost', () => {
      const summary = validator.getSummary('http://localhost:3000');
      expect(summary).toContain('localhost');
      expect(summary).toContain('local');
      expect(summary).toContain('Target Validation Summary');
    });

    it('should return formatted summary for staging', () => {
      const summary = validator.getSummary('https://app.staging.example.com');
      expect(summary).toContain('staging');
      expect(summary).toContain('app.staging.example.com');
    });

    it('should return formatted summary for production', () => {
      const summary = validator.getSummary('https://example.com');
      expect(summary).toContain('production');
      expect(summary).toContain('example.com');
    });

    it('should include warnings in summary when present', () => {
      const summary = validator.getSummary('http://example.com');
      expect(summary).toContain('Warnings');
    });

    it('should be readable for console output', () => {
      const summary = validator.getSummary('https://example.com');
      expect(typeof summary).toBe('string');
      expect(summary.length).toBeGreaterThan(50);
    });

    it('should include recommendations in summary when present', () => {
      const summary = validator.getSummary('http://example.com');
      expect(summary).toContain('Recommendations');
    });
  });

  describe('Edge Cases', () => {
    it('should handle localhost.localdomain pattern', () => {
      const result = validator.validateUrl('http://localhost.localdomain:3000');
      expect(result.isLocal).toBe(true);
    });

    it('should handle different localhost port numbers', () => {
      expect(validator.validateUrl('http://localhost:3000').isLocal).toBe(true);
      expect(validator.validateUrl('http://localhost:8000').isLocal).toBe(true);
      expect(validator.validateUrl('http://localhost:9999').isLocal).toBe(true);
    });

    it('should handle case variations in domain names', () => {
      const result1 = validator.validateUrl('https://App.Staging.Example.com');
      const result2 = validator.validateUrl('https://app.staging.example.com');
      expect(result1.environment).toBe(result2.environment);
    });

    it('should handle very long URLs', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(1000);
      const result = validator.validateUrl(longUrl);
      expect(result.isValid).toBe(true);
    });

    it('should handle IPv4 addresses with ports', () => {
      const result = validator.validateUrl('http://192.168.1.1:8080');
      expect(result.isLocal).toBe(true);
    });

    it('should handle IPv4 private range correctly', () => {
      // 172.16.0.0 - 172.31.255.255 is private
      const result1 = validator.validateUrl('http://172.16.0.1');
      expect(result1.isLocal).toBe(true);

      const result2 = validator.validateUrl('http://172.31.255.255');
      expect(result2.isLocal).toBe(true);
    });
  });

  describe('Production Guardrails', () => {
    it('should warn about scanning non-local targets', () => {
      const result = validator.validateUrl('https://app.staging.example.com');
      expect(result.warnings.length).toBeGreaterThan(0);
      expect(result.recommendations.some(r => r.includes('confirmation'))).toBe(true);
    });

    it('should block production scans by default', () => {
      const result = validator.shouldBlockActiveScan('https://api.example.com');
      expect(result.shouldBlock).toBe(true);
    });

    it('should allow override only with explicit flag', () => {
      const blocked = validator.shouldBlockActiveScan('https://api.example.com');
      expect(blocked.shouldBlock).toBe(true);

      const allowed = validator.shouldBlockActiveScan('https://api.example.com', {
        confirmProduction: true,
      });
      expect(allowed.shouldBlock).toBe(false);
    });

    it('should detect HTTPS compliance issues', () => {
      const result = validator.validateUrl('http://secure-api.example.com:443');
      expect(result.isProduction).toBe(true);
      const hasHTTPSWarning = result.warnings.some(w => w.toUpperCase().includes('HTTPS'));
      expect(hasHTTPSWarning).toBe(true);
    });
  });
});
