/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for CVE-based risk quantification.
 */
export type api__algorithmic_router__CVERiskRequest = {
    /**
     * CVE identifier
     */
    cve_id: string;
    /**
     * CVSS score (default 5.0 if unknown)
     */
    cvss_score?: number;
    /**
     * EPSS score (0-1)
     */
    epss_score?: number;
    /**
     * Whether in CISA KEV catalog
     */
    kev_listed?: boolean;
    /**
     * Asset value in dollars
     */
    asset_value?: number;
    /**
     * Whether vulnerable code is reachable
     */
    is_reachable?: boolean;
    /**
     * Number of simulations
     */
    simulations?: number;
};

