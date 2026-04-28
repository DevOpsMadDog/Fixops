/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__alert_enrichment_router__RegisterSourceRequest = {
    /**
     * Unique source name
     */
    source_name: string;
    /**
     * threat_intel | asset_db | vuln_db | geolocation | reputation
     */
    source_type: string;
    /**
     * Priority (lower = higher priority)
     */
    priority?: number;
    /**
     * API key (stored as SHA-256 hash)
     */
    api_key?: string;
};

