/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RawIngestIn = {
    org_id?: string;
    /**
     * Raw syslog (RFC 3164/5424) or CEF log line
     */
    raw: string;
    /**
     * 'syslog' | 'cef' | 'auto' (default — auto-detected from content)
     */
    format?: string;
};

