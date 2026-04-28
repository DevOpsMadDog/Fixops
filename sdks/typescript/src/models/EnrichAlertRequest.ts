/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type EnrichAlertRequest = {
    /**
     * Enrichment source name
     */
    source_name: string;
    /**
     * ioc_match | geolocation | asset_info | vuln_info | reputation | error
     */
    result_type: string;
    /**
     * Enrichment result payload
     */
    result_data?: string;
    /**
     * Number of IOC matches found
     */
    ioc_matches?: number;
    /**
     * Confidence score 0.0-1.0
     */
    confidence_score?: number;
};

