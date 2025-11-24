import { Vulnerability } from '../../types/vulnerability';
import { AttackSurface } from '../../scanners/active/DomExplorer';
import { InjectionResult } from '../../scanners/active/PayloadInjector';
import { Page } from 'playwright';
export interface ActiveDetectorContext {
    page: Page;
    attackSurfaces: AttackSurface[];
    baseUrl: string;
}
export interface IActiveDetector {
    readonly name: string;
    detect(context: ActiveDetectorContext): Promise<Vulnerability[]>;
    analyzeInjectionResult(result: InjectionResult): Promise<Vulnerability[]>;
    validate(): Promise<boolean>;
    getPayloads(): string[];
}
//# sourceMappingURL=IActiveDetector.d.ts.map