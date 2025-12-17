/**
 * Tests for Sensitive Data Pattern Validation
 * Verifies that false positives are properly filtered
 */

import {
  PHONE_PATTERNS,
  SSN_PATTERNS,
  EMAIL_PATTERNS,
  API_KEY_PATTERNS,
  PASSWORD_PATTERNS,
  CREDIT_CARD_PATTERNS,
} from '../../src/utils/patterns/sensitive-data-patterns';

describe('Sensitive Data Patterns', () => {
  describe('Phone Number Patterns', () => {
    const testPhone = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of PHONE_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    describe('Should NOT match (false positives)', () => {
      it('should not match version numbers', () => {
        expect(testPhone('{"version":"19.1.0"}')).toHaveLength(0);
        expect(testPhone('v2.2.4')).toHaveLength(0);
        expect(testPhone('3.1.0')).toHaveLength(0);
      });

      it('should not match simple IDs or quantities', () => {
        expect(testPhone('{"id":1}')).toHaveLength(0);
        expect(testPhone('{"quantity":75}')).toHaveLength(0);
        expect(testPhone('{"ProductId":1,"id":1,"quantity":75}')).toHaveLength(0);
      });

      it('should not match timestamps', () => {
        expect(testPhone('2025-12-15T13:42:59.358Z')).toHaveLength(0);
        expect(testPhone('1765812534850')).toHaveLength(0);
      });

      it('should not match webpack chunk IDs', () => {
        expect(testPhone('d(467),L=d(7705),i=d(2615)')).toHaveLength(0);
      });

      it('should not match port numbers', () => {
        expect(testPhone('localhost:3000')).toHaveLength(0);
        expect(testPhone('port: 8080')).toHaveLength(0);
      });

      it('should not match IP addresses', () => {
        expect(testPhone('192.168.99.100')).toHaveLength(0);
        expect(testPhone('10.0.0.1')).toHaveLength(0);
        expect(testPhone('172.16.0.1')).toHaveLength(0);
      });
    });

    describe('Should match (true positives)', () => {
      it('should match E.164 international format', () => {
        expect(testPhone('+14155551234')).toContain('+14155551234');
        expect(testPhone('+442071234567')).toContain('+442071234567');
      });

      it('should match US formatted phone numbers', () => {
        expect(testPhone('(415) 555-1234')).toContain('(415) 555-1234');
        expect(testPhone('415-555-1234')).toContain('415-555-1234');
        // Note: dot-separated format requires negative lookahead to avoid IP conflicts
        // so we test it separately from IP-like patterns
      });
    });
  });

  describe('SSN/CNP Patterns', () => {
    const testSSN = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of SSN_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    describe('Should NOT match (false positives)', () => {
      it('should not match webpack chunk IDs', () => {
        expect(testSSN('d(467),L=d(7705),i=d(2615)')).toHaveLength(0);
        expect(testSSN('var S=d(467),L=d(7705)')).toHaveLength(0);
      });

      it('should not match random 13-digit numbers without context', () => {
        // Standalone 13-digit numbers should not match (removed aggressive pattern)
        expect(testSSN('1005432100502')).toHaveLength(0);
      });

      it('should not match timestamps', () => {
        expect(testSSN('1765812534850')).toHaveLength(0);
      });
    });

    describe('Should match (true positives)', () => {
      it('should match US SSN format (XXX-XX-XXXX)', () => {
        expect(testSSN('123-45-6789')).toContain('123-45-6789');
        expect(testSSN('SSN: 123-45-6789')).toContain('123-45-6789');
      });

      it('should match SSN in JSON context', () => {
        const result = testSSN('"ssn": "123-45-6789"');
        expect(result.length).toBeGreaterThan(0);
      });

      it('should match CNP in JSON context', () => {
        const result = testSSN('"cnp": "1850512345678"');
        expect(result.length).toBeGreaterThan(0);
      });
    });
  });

  describe('Email Patterns', () => {
    const testEmail = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of EMAIL_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    it('should match valid email addresses', () => {
      expect(testEmail('test@example.com')).toContain('test@example.com');
      expect(testEmail('user.name@domain.org')).toContain('user.name@domain.org');
    });

    it('should not match invalid patterns', () => {
      expect(testEmail('not-an-email')).toHaveLength(0);
      expect(testEmail('@nodomain')).toHaveLength(0);
    });
  });

  describe('Credit Card Patterns', () => {
    const testCC = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of CREDIT_CARD_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    it('should match Visa card numbers', () => {
      expect(testCC('4111111111111111')).toContain('4111111111111111');
      expect(testCC('4111-1111-1111-1111')).toContain('4111-1111-1111-1111');
    });

    it('should match Mastercard numbers', () => {
      expect(testCC('5555555555554444')).toContain('5555555555554444');
    });

    it('should not match random numbers', () => {
      expect(testCC('1234567890123456')).toHaveLength(0);
    });
  });

  describe('API Key Patterns', () => {
    const testAPIKey = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of API_KEY_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    it('should match AWS access key IDs', () => {
      expect(testAPIKey('AKIAIOSFODNN7EXAMPLE').length).toBeGreaterThan(0);
    });

    it('should match GitHub tokens', () => {
      expect(testAPIKey('ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx').length).toBeGreaterThan(0);
    });

    it('should match generic API key patterns', () => {
      expect(testAPIKey('api_key="my_test_api_key_123456789"').length).toBeGreaterThan(0);
    });
  });

  describe('Password Patterns', () => {
    const testPassword = (input: string): string[] => {
      const results: string[] = [];
      for (const pattern of PASSWORD_PATTERNS) {
        pattern.lastIndex = 0;
        const matches = input.match(pattern);
        if (matches) results.push(...matches);
      }
      return results;
    };

    it('should match JSON password fields', () => {
      expect(testPassword('"password": "secretpass123"').length).toBeGreaterThan(0);
      expect(testPassword("'password': 'secretpass123'").length).toBeGreaterThan(0);
    });

    it('should match XML password fields', () => {
      expect(testPassword('<password>secretpass</password>').length).toBeGreaterThan(0);
    });
  });
});
