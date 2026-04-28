/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_brief_router__AddThreatRequest = {
    /**
     * Threat name (required)
     */
    threat_name: string;
    /**
     * Threat actor / APT group
     */
    threat_actor?: (string | null);
    /**
     * critical | high | medium | low | informational
     */
    severity?: string;
    /**
     * Affected industry sectors
     */
    affected_sectors?: (Array<string> | null);
    /**
     * Number of IOCs associated
     */
    ioc_count?: number;
    /**
     * MITRE ATT&CK tactics
     */
    mitre_tactics?: (Array<string> | null);
};

