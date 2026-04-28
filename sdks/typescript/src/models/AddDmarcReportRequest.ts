/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddDmarcReportRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Domain ID the report covers
     */
    domain_id: string;
    /**
     * Report date (YYYY-MM-DD)
     */
    date?: (string | null);
    /**
     * Messages that passed DMARC
     */
    pass_count?: number;
    /**
     * Messages that failed DMARC
     */
    fail_count?: number;
    /**
     * Messages quarantined
     */
    quarantine_count?: number;
    /**
     * Messages rejected
     */
    reject_count?: number;
    /**
     * Observed source IPs
     */
    source_ips?: Array<string>;
};

