/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddDomainRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Domain name (e.g. example.com)
     */
    domain: string;
    /**
     * SPF TXT record value
     */
    spf_record?: (string | null);
    /**
     * DKIM selector name
     */
    dkim_selector?: (string | null);
    /**
     * DMARC policy: none | quarantine | reject | missing
     */
    dmarc_policy?: (string | null);
};

