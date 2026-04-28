/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__forensics_readiness_router__RegisterSourceRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Evidence source name
     */
    name: string;
    /**
     * endpoint_logs/network_pcap/cloud_trail/email_archive/database_audit/identity_logs/application_logs
     */
    source_type: string;
    /**
     * Data retention period in days
     */
    retention_days?: number;
    /**
     * agent/api/syslog/manual
     */
    collection_method?: string;
    status?: string;
};

