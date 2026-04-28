/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type api__siem_router__AddTargetRequest = {
    /**
     * Human-readable target name
     */
    name: string;
    /**
     * syslog_tcp, syslog_udp, splunk_hec, webhook
     */
    transport: string;
    /**
     * cef, leef, json
     */
    output_format?: string;
    /**
     * Target host (syslog)
     */
    host?: string;
    /**
     * Target port (syslog)
     */
    port?: number;
    /**
     * URL (Splunk HEC / webhook)
     */
    url?: string;
    /**
     * Auth token (Splunk HEC / webhook)
     */
    token?: string;
    /**
     * Splunk index
     */
    index?: string;
    /**
     * Source identifier
     */
    source?: string;
    /**
     * Sourcetype
     */
    sourcetype?: string;
    enabled?: boolean;
    /**
     * Event types to forward (empty=all)
     */
    event_filters?: Array<string>;
};

