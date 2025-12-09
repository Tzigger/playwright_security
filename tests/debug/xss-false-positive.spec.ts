import { test, expect } from '@playwright/test';
import { XssDetector } from '../../src/detectors/active/XssDetector';
import { AttackSurface, AttackSurfaceType, InjectionContext } from '../../src/scanners/active/DomExplorer';

test.describe('XSS False Positives', () => {
  test('Permissive mode does not flag generic script tags as reflection', async () => {
    const detector = new XssDetector({ permissiveMode: true });
    const payload = '<script>alert(1)</script>';
    
    // Simulate a response that has existing script tags but NOT our payload
    const body = `
      <html>
      <head>
        <script>
          console.log('existing script');
        </script>
      </head>
      <body>
        <h1>Title</h1>
        <script src="/js/main.js"></script>
      </body>
      </html>
    `;

    const result = {
      surface: {
        name: 'test',
        type: AttackSurfaceType.FORM_INPUT,
        context: InjectionContext.HTML
      } as AttackSurface,
      payload: payload,
      response: {
        body: body,
        url: 'http://localhost/test',
        status: 200,
        headers: {}
      }
    };

    // Access private method for testing logic
    // @ts-ignore
    const analysis = detector.analyzeReflection(result, payload);
    
    expect(analysis.reflected).toBe(false);
  });

  test('Permissive mode flags actual payload reflection', async () => {
    const detector = new XssDetector({ permissiveMode: true });
    const payload = '<script>alert(1)</script>';
    
    const body = `
      <html>
      <body>
        <h1>Search Results</h1>
        You searched for: <script>alert(1)</script>
      </body>
      </html>
    `;

    const result = {
        surface: {
          name: 'test',
          type: AttackSurfaceType.FORM_INPUT,
          context: InjectionContext.HTML
        } as AttackSurface,
        payload: payload,
        response: {
          body: body,
          url: 'http://localhost/test',
          status: 200,
          headers: {}
        }
      };

    // @ts-ignore
    const analysis = detector.analyzeReflection(result, payload);
    
    expect(analysis.reflected).toBe(true);
  });
});
