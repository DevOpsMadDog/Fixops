/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Optional toggles for a sync_all run.
 */
export type apps__api__threat_intel_connector_router__SyncRequest = {
    /**
     * Pull from MISP feeds
     */
    run_misp?: boolean;
    /**
     * Pull from CIRCL CVE feed
     */
    run_circl?: boolean;
    /**
     * Pull from PhishTank
     */
    run_phishtank?: boolean;
    /**
     * Pull from AlienVault OTX
     */
    run_otx?: boolean;
    /**
     * Pull from GitHub Advisory Database (GHSA)
     */
    run_ghsa?: boolean;
    /**
     * Cross-correlate IoCs against tenant findings
     */
    run_correlation?: boolean;
    /**
     * Override default MISP feed URLs (max 10).
     */
    misp_feed_urls?: (Array<string> | null);
};

