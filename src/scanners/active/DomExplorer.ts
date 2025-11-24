import { Logger } from '../../utils/logger/Logger';
import { LogLevel } from '../../types/enums';
import { Page } from 'playwright';

/**
 * Tipuri de elemente care pot fi atacate
 */
export enum AttackSurfaceType {
  FORM_INPUT = 'form-input',
  URL_PARAMETER = 'url-parameter',
  LINK = 'link',
  BUTTON = 'button',
  COOKIE = 'cookie',
  HEADER = 'header',
  JSON_BODY = 'json-body',
}

/**
 * Context de injecție pentru un element
 */
export enum InjectionContext {
  HTML = 'html',
  HTML_ATTRIBUTE = 'html-attribute',
  JAVASCRIPT = 'javascript',
  URL = 'url',
  SQL = 'sql',
  JSON = 'json',
  XML = 'xml',
}

/**
 * Punct de atac identificat în DOM
 */
export interface AttackSurface {
  id: string;
  type: AttackSurfaceType;
  element?: any; // Playwright element locator
  selector?: string;
  name: string;
  value?: string;
  context: InjectionContext;
  metadata: {
    formAction?: string;
    formMethod?: string;
    inputType?: string;
    url?: string;
    parameterName?: string;
    [key: string]: any;
  };
}

/**
 * Formular identificat în pagină
 */
export interface FormInfo {
  action: string;
  method: string;
  inputs: AttackSurface[];
  submitButton?: any;
}

/**
 * DomExplorer - Explorează DOM-ul pentru a identifica suprafețe de atac
 * Responsabilități:
 * - Identifică formulare și input-uri
 * - Descoperă parametri URL
 * - Găsește link-uri pentru crawling
 * - Detectează context de injecție
 */
export class DomExplorer {
  private logger: Logger;

  constructor(logLevel: LogLevel = LogLevel.INFO) {
    this.logger = new Logger(logLevel, 'DomExplorer');
  }

  /**
   * Explorează pagina pentru toate suprafețele de atac
   */
  public async explore(page: Page): Promise<AttackSurface[]> {
    this.logger.info('Starting DOM exploration');
    const surfaces: AttackSurface[] = [];

    try {
      // 1. Descoperă input-uri din formulare
      const formSurfaces = await this.discoverFormInputs(page);
      surfaces.push(...formSurfaces);

      // 2. Descoperă parametri URL
      const urlSurfaces = await this.discoverUrlParameters(page);
      surfaces.push(...urlSurfaces);

      // 3. Descoperă link-uri pentru crawling
      const linkSurfaces = await this.discoverLinks(page);
      surfaces.push(...linkSurfaces);

      // 4. Descoperă cookies
      const cookieSurfaces = await this.discoverCookies(page);
      surfaces.push(...cookieSurfaces);

      this.logger.info(`DOM exploration completed. Found ${surfaces.length} attack surfaces`);
    } catch (error) {
      this.logger.error(`Error during DOM exploration: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă toate formularele din pagină
   */
  public async discoverForms(page: Page): Promise<FormInfo[]> {
    const forms: FormInfo[] = [];

    try {
      const formElements = await page.$$('form');
      
      for (const form of formElements) {
        const action = (await form.getAttribute('action')) || page.url();
        const method = ((await form.getAttribute('method')) || 'GET').toUpperCase();
        
        const inputs: AttackSurface[] = [];
        const inputElements = await form.$$('input, textarea, select');
        
        for (let i = 0; i < inputElements.length; i++) {
          const input = inputElements[i];
          if (!input) continue;
          const name = await input.getAttribute('name');
          const type = await input.getAttribute('type') || 'text';
          const value = await input.getAttribute('value') || '';
          
          if (name && type !== 'submit' && type !== 'button') {
            inputs.push({
              id: `form-input-${i}`,
              type: AttackSurfaceType.FORM_INPUT,
              element: input,
              selector: `input[name="${name}"]`,
              name,
              value,
              context: this.determineContext(type, name),
              metadata: {
                formAction: action,
                formMethod: method,
                inputType: type,
              },
            });
          }
        }

        const submitButton = await form.$('button[type="submit"], input[type="submit"]');
        
        forms.push({
          action,
          method,
          inputs,
          submitButton,
        });
      }

      this.logger.debug(`Discovered ${forms.length} forms`);
    } catch (error) {
      this.logger.error(`Error discovering forms: ${error}`);
    }

    return forms;
  }

  /**
   * Descoperă input-uri din formulare
   */
  private async discoverFormInputs(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];
    const forms = await this.discoverForms(page);
    
    forms.forEach(form => {
      surfaces.push(...form.inputs);
    });

    return surfaces;
  }

  /**
   * Descoperă parametri URL
   */
  private async discoverUrlParameters(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const url = new URL(page.url());
      const params = url.searchParams;

      let index = 0;
      params.forEach((value, key) => {
        surfaces.push({
          id: `url-param-${index++}`,
          type: AttackSurfaceType.URL_PARAMETER,
          name: key,
          value,
          context: InjectionContext.URL,
          metadata: {
            url: page.url(),
            parameterName: key,
          },
        });
      });

      this.logger.debug(`Discovered ${surfaces.length} URL parameters`);
    } catch (error) {
      this.logger.debug(`Error discovering URL parameters: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă link-uri pentru crawling
   */
  private async discoverLinks(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const links = await page.$$eval('a[href]', (elements) =>
        elements.map((el: any) => ({
          href: el.href,
          text: el.textContent?.trim() || '',
        }))
      );

      const currentDomain = new URL(page.url()).hostname;

      links.forEach((link, index) => {
        try {
          const linkUrl = new URL(link.href);
          // Doar link-uri din același domeniu
          if (linkUrl.hostname === currentDomain) {
            surfaces.push({
              id: `link-${index}`,
              type: AttackSurfaceType.LINK,
              name: link.text || link.href,
              value: link.href,
              context: InjectionContext.URL,
              metadata: {
                url: link.href,
                text: link.text,
              },
            });
          }
        } catch (e) {
          // Invalid URL, skip
        }
      });

      this.logger.debug(`Discovered ${surfaces.length} links`);
    } catch (error) {
      this.logger.error(`Error discovering links: ${error}`);
    }

    return surfaces;
  }

  /**
   * Descoperă cookies
   */
  private async discoverCookies(page: Page): Promise<AttackSurface[]> {
    const surfaces: AttackSurface[] = [];

    try {
      const cookies = await page.context().cookies();

      cookies.forEach((cookie, index) => {
        surfaces.push({
          id: `cookie-${index}`,
          type: AttackSurfaceType.COOKIE,
          name: cookie.name,
          value: cookie.value,
          context: InjectionContext.URL, // Cookies are usually URL-encoded
          metadata: {
            domain: cookie.domain,
            path: cookie.path,
            secure: cookie.secure,
            httpOnly: cookie.httpOnly,
            sameSite: cookie.sameSite,
          },
        });
      });

      this.logger.debug(`Discovered ${cookies.length} cookies`);
    } catch (error) {
      this.logger.error(`Error discovering cookies: ${error}`);
    }

    return surfaces;
  }

  /**
   * Determină contextul de injecție bazat pe tip și nume
   */
  private determineContext(inputType: string, name: string): InjectionContext {
    const lowerName = name.toLowerCase();

    // SQL context indicators
    if (
      lowerName.includes('search') ||
      lowerName.includes('query') ||
      lowerName.includes('id') ||
      lowerName.includes('user')
    ) {
      return InjectionContext.SQL;
    }

    // JavaScript context indicators
    if (lowerName.includes('callback') || lowerName.includes('script')) {
      return InjectionContext.JAVASCRIPT;
    }

    // URL context
    if (inputType === 'url' || lowerName.includes('url') || lowerName.includes('link')) {
      return InjectionContext.URL;
    }

    // Default to HTML context
    return InjectionContext.HTML;
  }

  /**
   * Filtrează suprafețele de atac după tip
   */
  public filterByType(surfaces: AttackSurface[], type: AttackSurfaceType): AttackSurface[] {
    return surfaces.filter((s) => s.type === type);
  }

  /**
   * Filtrează suprafețele de atac după context
   */
  public filterByContext(surfaces: AttackSurface[], context: InjectionContext): AttackSurface[] {
    return surfaces.filter((s) => s.context === context);
  }

  /**
   * Găsește input-uri care pot fi atacate pentru SQL injection
   */
  public getSqlInjectionTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces.filter(
      (s) =>
        s.context === InjectionContext.SQL ||
        s.name.toLowerCase().includes('search') ||
        s.name.toLowerCase().includes('id') ||
        s.name.toLowerCase().includes('query')
    );
  }

  /**
   * Găsește input-uri care pot fi atacate pentru XSS
   */
  public getXssTargets(surfaces: AttackSurface[]): AttackSurface[] {
    return surfaces.filter(
      (s) =>
        s.context === InjectionContext.HTML ||
        s.context === InjectionContext.JAVASCRIPT ||
        s.type === AttackSurfaceType.FORM_INPUT ||
        s.type === AttackSurfaceType.URL_PARAMETER
    );
  }
}
