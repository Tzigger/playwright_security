import { PayloadFilter } from '@utils/PayloadFilter';

describe('PayloadFilter', () => {
  let filter: PayloadFilter;

  beforeEach(() => {
    filter = new PayloadFilter();
  });

  describe('isSafe()', () => {
    describe('SQL Destructive Patterns', () => {
      it('should mark DROP TABLE payloads as unsafe', () => {
        const payload = "'; DROP TABLE users--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark DELETE FROM payloads as unsafe', () => {
        const payload = "'; DELETE FROM users WHERE 1=1--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark TRUNCATE payloads as unsafe', () => {
        const payload = "'; TRUNCATE TABLE users--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark ALTER TABLE payloads as unsafe', () => {
        const payload = "'; ALTER TABLE users DROP COLUMN password--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark UPDATE payloads as unsafe', () => {
        const payload = "'; UPDATE users SET admin=1--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark INSERT payloads as unsafe', () => {
        const payload = "'; INSERT INTO users(id, name, pass) VALUES (1, 'hacker', 'pass')--";
        expect(filter.isSafe(payload)).toBe(false);
      });
    });

    describe('SQL Execution Patterns', () => {
      it('should mark EXEC payloads as unsafe', () => {
        const payload = "'; EXEC xp_cmdshell 'del C:\\*.*'--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark xp_cmdshell payloads as unsafe', () => {
        const payload = "1; xp_cmdshell 'whoami';--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark EXECUTE payloads as unsafe', () => {
        const payload = "'; xp_cmdshell 'whoami'--";
        expect(filter.isSafe(payload)).toBe(false);
      });
    });

    describe('System Command Patterns', () => {
      it('should mark system() calls as unsafe', () => {
        const payload = "'; system('rm -rf /')--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark shell_exec() calls as unsafe', () => {
        const payload = "'); shell_exec('whoami'); //";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark exec() calls as unsafe', () => {
        const payload = "` | exec('id') | `";
        expect(filter.isSafe(payload)).toBe(false);
      });
    });

    describe('File Operation Patterns', () => {
      it('should mark OUTFILE payloads as unsafe', () => {
        const payload = "' UNION SELECT @@version INTO OUTFILE '/tmp/test'--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark LOAD_FILE payloads as unsafe', () => {
        const payload = "' UNION SELECT LOAD_FILE('/etc/passwd')--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark DUMPFILE payloads as unsafe', () => {
        const payload = "' UNION SELECT password INTO DUMPFILE '/tmp/pass'--";
        expect(filter.isSafe(payload)).toBe(false);
      });
    });

    describe('Permission & Privilege Patterns', () => {
      it('should mark GRANT payloads as unsafe', () => {
        const payload = "'; GRANT ALL PRIVILEGES ON *.* TO 'attacker'@'localhost'--";
        expect(filter.isSafe(payload)).toBe(false);
      });

      it('should mark REVOKE payloads as unsafe', () => {
        const payload = "'; REVOKE ALL PRIVILEGES ON *.* FROM 'user'@'localhost'--";
        expect(filter.isSafe(payload)).toBe(false);
      });
    });

    describe('Safe Payloads', () => {
      it('should mark OR 1=1 payloads as safe', () => {
        const payload = "' OR '1'='1";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark UNION SELECT payloads as safe', () => {
        const payload = "' UNION SELECT @@version--";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark AND SLEEP payloads as safe', () => {
        const payload = "' AND SLEEP(5)--";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark TIME-BASED blind SQLi payloads as safe', () => {
        const payload = "' AND IF(1=1, SLEEP(5), 0)--";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark comment sequences as safe', () => {
        const payload = "' OR '1'='1' #";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark XSS payloads as safe', () => {
        const payload = "<img src=x onerror='alert(1)'>";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark normal strings as safe', () => {
        const payload = "normal user input";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark empty strings as safe', () => {
        const payload = "";
        expect(filter.isSafe(payload)).toBe(true);
      });

      it('should mark numbers as safe', () => {
        const payload = "123";
        expect(filter.isSafe(payload)).toBe(true);
      });
    });

    describe('Case Insensitivity', () => {
      it('should detect DROP in any case', () => {
        expect(filter.isSafe("drop table users")).toBe(false);
        expect(filter.isSafe("DROP TABLE users")).toBe(false);
        expect(filter.isSafe("DrOp TaBlE users")).toBe(false);
      });

      it('should detect DELETE in any case', () => {
        expect(filter.isSafe("delete from users")).toBe(false);
        expect(filter.isSafe("DELETE FROM users")).toBe(false);
        expect(filter.isSafe("DeLeTe FrOm users")).toBe(false);
      });
    });
  });

  describe('getSafetyLevel()', () => {
    it('should return "safe" for safe payloads', () => {
      const payload = "' OR '1'='1";
      expect(filter.getSafetyLevel(payload)).toBe('safe');
    });

    it('should return "dangerous" for destructive payloads', () => {
      const payload = "'; DROP TABLE users--";
      expect(filter.getSafetyLevel(payload)).toBe('dangerous');
    });

    it('should handle time-based blind SQLi payloads appropriately', () => {
      const payload = "' AND SLEEP(5)--";
      const level = filter.getSafetyLevel(payload);
      // SLEEP is in keywords but passes pattern check, so it's 'warning' or 'safe'
      expect(['safe', 'warning']).toContain(level);
    });
  });

  describe('filterPayloads()', () => {
    it('should remove dangerous payloads from list', () => {
      const payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "'; DELETE FROM users--",
      ];

      const filtered = filter.filterPayloads(payloads);
      
      expect(filtered).toContain("' OR '1'='1");
      expect(filtered).toContain("' UNION SELECT NULL--");
      expect(filtered).not.toContain("'; DROP TABLE users--");
      expect(filtered).not.toContain("'; DELETE FROM users--");
      expect(filtered.length).toBe(2);
    });

    it('should preserve all safe payloads', () => {
      const safePayloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND SLEEP(5)--",
        "' OR 1=1#",
      ];

      const filtered = filter.filterPayloads(safePayloads);
      
      expect(filtered.length).toBe(safePayloads.length);
      expect(filtered).toEqual(safePayloads);
    });

    it('should return empty array if all payloads are dangerous', () => {
      const dangerousPayloads = [
        "'; DROP TABLE users--",
        "'; DELETE FROM users--",
        "'; TRUNCATE TABLE users--",
      ];

      const filtered = filter.filterPayloads(dangerousPayloads);
      
      expect(filtered.length).toBe(0);
      expect(filtered).toEqual([]);
    });

    it('should handle empty payload list', () => {
      const filtered = filter.filterPayloads([]);
      expect(filtered).toEqual([]);
    });

    it('should handle mixed case payloads', () => {
      const payloads = [
        "' OR '1'='1",
        "'; drop table users--",
        "' UNION SELECT NULL--",
      ];

      const filtered = filter.filterPayloads(payloads);
      
      expect(filtered.length).toBe(2);
      expect(filtered).not.toContain("'; drop table users--");
    });
  });

  describe('getFilterStats()', () => {
    it('should return correct statistics for mixed payloads', () => {
      const payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users--",
        "' UNION SELECT NULL--",
        "'; DELETE FROM users--",
        "' AND SLEEP(5)--",
      ];

      const stats = filter.getFilterStats(payloads);

      expect(stats.total).toBe(5);
      expect(stats.safe).toBe(2);
      expect(stats.dangerous).toBe(2);
      expect(stats.warning).toBe(1);
    });

    it('should return zeros for empty list', () => {
      const stats = filter.getFilterStats([]);

      expect(stats.total).toBe(0);
      expect(stats.safe).toBe(0);
      expect(stats.dangerous).toBe(0);
      expect(stats.warning).toBe(0);
    });

    it('should return all safe for safe payloads', () => {
      const payloads = [
        "' OR '1'='1",
        "' UNION SELECT NULL--",
        "' AND 1=1--",
      ];

      const stats = filter.getFilterStats(payloads);

      expect(stats.total).toBe(3);
      expect(stats.safe).toBeGreaterThanOrEqual(2); // At least 2 should be safe
      expect(stats.dangerous).toBe(0);
    });

    it('should return correct counts for edge cases', () => {
      const payloads = [
        "'; DROP TABLE users--",
      ];

      const stats = filter.getFilterStats(payloads);

      expect(stats.total).toBe(1);
      expect(stats.dangerous).toBe(1);
      expect(stats.safe).toBe(0);
      expect(stats.warning).toBe(0);
    });
  });

  describe('Edge Cases', () => {
    it('should handle very long payloads', () => {
      const longPayload = "' OR '1'='1" + "A".repeat(10000);
      expect(filter.isSafe(longPayload)).toBe(true);
    });

    it('should handle payloads with special characters', () => {
      const payload = "' OR 1=1 /*! DROP TABLE users */--";
      expect(filter.isSafe(payload)).toBe(false);
    });

    it('should handle null-byte injection attempts', () => {
      const payload = "'; DROP TABLE users\x00--";
      expect(filter.isSafe(payload)).toBe(false);
    });

    it('should handle unicode characters', () => {
      const payload = "'; DROP TABLE users--你好";
      expect(filter.isSafe(payload)).toBe(false);
    });

    it('should handle mixed encoding attempts', () => {
      const payload = "'; %44%52%4F%50 TABLE users--";
      expect(filter.isSafe(payload)).toBe(true); // Hex encoding not detected (detection is runtime)
    });
  });
});
