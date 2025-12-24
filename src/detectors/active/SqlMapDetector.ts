import { IActiveDetector, ActiveDetectorContext } from '../../core/interfaces/IActiveDetector';
import { Vulnerability } from '../../types/vulnerability';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
import { SqlMapWrapper } from '../../utils/external/SqlMapWrapper';
import { AttackSurfaceType } from '../../scanners/active/DomExplorer';
import { VulnerabilitySeverity, VulnerabilityCategory } from '../../types/enums';

export class SqlMapDetector implements IActiveDetector {
  public readonly name = 'SqlMapDetector';
  private sqlmap: SqlMapWrapper;

  constructor() {
    this.sqlmap = new SqlMapWrapper();
  }

  public async validate(): Promise<boolean> {
    // Check if sqlmap is available?
    // For now assume yes or let it fail gracefully
    return true;
  }

  public getPayloads(): string[] {
    return ['(Delegated to sqlmap)'];
  }

  public async detect(context: ActiveDetectorContext): Promise<Vulnerability[]> {
    const vulnerabilities: Vulnerability[] = [];
    
    // Filter for API endpoints only, as requested
    // Also include URL parameters if they look like API calls (e.g. /rest/, /api/)
    const apiSurfaces = context.attackSurfaces.filter(s => {
        if (s.type === AttackSurfaceType.API_ENDPOINT) return true;
        
        if (s.type === AttackSurfaceType.URL_PARAMETER) {
            const url = s.metadata['url'] as string;
            if (url && (url.includes('/rest/') || url.includes('/api/') || url.includes('/v1/'))) {
                return true;
            }
        }
        return false;
    });

    if (apiSurfaces.length === 0) return [];

    for (const surface of apiSurfaces) {
      let url = '';
      let method = 'GET';

      if (surface.type === AttackSurfaceType.API_ENDPOINT) {
          const relativeUrl = surface.metadata['url'] as string;
          if (!relativeUrl) continue;
          url = new URL(relativeUrl, context.baseUrl).toString();
          method = (surface.metadata['method'] as string) || 'GET';
      } else if (surface.type === AttackSurfaceType.URL_PARAMETER) {
          url = surface.metadata['url'] as string;
          // For URL parameters, the method is usually GET unless specified otherwise
          method = 'GET'; 
      }

      if (!url) continue;
      
      // Get cookies from page context
      const cookies = await context.page.context().cookies(url);
      const cookieString = cookies.map(c => `${c.name}=${c.value}`).join('; ');

      const result = await this.sqlmap.scan({
        url,
        method,
        cookie: cookieString,
        batch: true,
        level: 1, // Keep it fast
        risk: 1
      });

      if (result.vulnerabilities.length > 0) {
        for (const vuln of result.vulnerabilities) {
          vulnerabilities.push({
            id: `sqlmap-${Date.now()}-${Math.random()}`,
            title: `SQL Injection (via sqlmap)`,
            description: `sqlmap detected a vulnerability: Parameter: ${vuln.parameter} - Type: ${vuln.type}`,
            severity: VulnerabilitySeverity.HIGH,
            category: VulnerabilityCategory.INJECTION,
            url,
            evidence: {
              request: {
                url,
                method,
                headers: { Cookie: cookieString },
                body: vuln.payload // Show the payload in the request body or a specific field
              },
              response: {
                status: 200, // Placeholder
                body: `Payload used: ${vuln.payload}\n\nFull Output Snippet:\n${result.rawOutput.substring(0, 2000)}`
              },
              payload: vuln.payload // Explicit payload field if supported by the type
            },
            confirmed: true, // sqlmap is usually reliable
            remediation: 'Sanitize all inputs using parameterized queries or prepared statements.',
            references: ['https://sqlmap.org/'],
            timestamp: new Date()
          });
        }
      }
    }

    return vulnerabilities;
  }

  public async analyzeInjectionResult(_result: InjectionResult): Promise<Vulnerability[]> {
    return [];
  }
}
