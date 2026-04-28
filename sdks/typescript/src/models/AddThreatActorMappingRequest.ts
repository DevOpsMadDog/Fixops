/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to add a threat actor to CVE mapping.
 */
export type AddThreatActorMappingRequest = {
    cve_id: string;
    threat_actor: string;
    campaign?: (string | null);
    first_seen?: (string | null);
    last_seen?: (string | null);
    target_sectors?: (Array<string> | null);
    target_countries?: (Array<string> | null);
    ttps?: (Array<string> | null);
    /**
     * low, medium, high
     */
    confidence?: string;
    source?: (string | null);
};

