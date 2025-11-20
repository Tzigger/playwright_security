export declare const SQL_INJECTION_PAYLOADS: string[];
export declare const XSS_PAYLOADS: string[];
export declare const COMMAND_INJECTION_PAYLOADS: string[];
export declare const PATH_TRAVERSAL_PAYLOADS: string[];
export declare const LDAP_INJECTION_PAYLOADS: string[];
export declare const XML_INJECTION_PAYLOADS: string[];
export declare const NOSQL_INJECTION_PAYLOADS: string[];
export declare const SPECIAL_CHARACTERS: string[];
export declare const LONG_STRING_PAYLOADS: string[];
export interface AttackVectorMetadata {
    payloads: string[];
    category: string;
    description: string;
    detectionSignatures?: string[];
}
export declare const ATTACK_VECTOR_MAP: AttackVectorMetadata[];
export declare const ALL_PAYLOADS: string[];
//# sourceMappingURL=attack-vectors.d.ts.map