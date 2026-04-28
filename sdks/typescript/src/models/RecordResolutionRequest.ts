/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordResolutionRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Domain name (e.g. example.com)
     */
    domain: string;
    /**
     * IP address the domain resolved to
     */
    resolved_ip: string;
    /**
     * DNS record type: A/AAAA/MX/NS/CNAME/TXT
     */
    record_type?: string;
    /**
     * Time-to-live in seconds
     */
    ttl?: number;
    /**
     * ISO8601 first seen timestamp
     */
    first_seen?: (string | null);
    /**
     * ISO8601 last seen timestamp
     */
    last_seen?: (string | null);
    /**
     * Data source: sensor/feed/query
     */
    source?: string;
};

