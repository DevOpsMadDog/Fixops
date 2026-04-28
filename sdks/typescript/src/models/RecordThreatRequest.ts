/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordThreatRequest = {
    org_id?: string;
    /**
     * Type: rogue_ap, evil_twin, deauth_attack, krack, pmkid, wardriving, eavesdropping
     */
    threat_type: string;
    /**
     * Severity: low, medium, high, critical
     */
    severity: string;
    ap_id?: (string | null);
    bssid?: (string | null);
    description?: (string | null);
};

