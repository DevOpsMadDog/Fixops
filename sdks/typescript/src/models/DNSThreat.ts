/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__network_security__Severity } from './core__network_security__Severity';
import type { DNSThreatType } from './DNSThreatType';
export type DNSThreat = {
    id?: string;
    org_id: string;
    threat_type: DNSThreatType;
    domain: string;
    resolver_ip?: (string | null);
    severity: core__network_security__Severity;
    description: string;
    entropy?: (number | null);
    detected_at?: string;
};

