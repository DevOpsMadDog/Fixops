/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__threat_attribution_router__AddIndicatorRequest = {
    org_id?: string;
    /**
     * Type: ttps, iocs, infrastructure, malware, victimology
     */
    indicator_type?: string;
    /**
     * Indicator value (IP, hash, domain, etc.)
     */
    value?: string;
    /**
     * Description of the indicator
     */
    description?: string;
    /**
     * ISO datetime first observed
     */
    first_seen?: (string | null);
    /**
     * ISO datetime last observed
     */
    last_seen?: (string | null);
};

