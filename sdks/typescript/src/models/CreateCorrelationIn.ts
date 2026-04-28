/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateCorrelationIn = {
    /**
     * Primary CVE identifier
     */
    primary_cve: string;
    /**
     * Related CVE IDs
     */
    related_cves?: Array<string>;
    /**
     * Affected asset IDs
     */
    asset_ids?: Array<string>;
    /**
     * attack_chain|shared_component|same_vendor|exploit_similarity|environmental
     */
    correlation_type?: string;
    /**
     * Risk multiplier clamped 0.1-10.0
     */
    risk_multiplier?: number;
    /**
     * Combined risk score
     */
    combined_risk_score?: number;
    /**
     * critical|high|medium|low
     */
    severity?: string;
};

