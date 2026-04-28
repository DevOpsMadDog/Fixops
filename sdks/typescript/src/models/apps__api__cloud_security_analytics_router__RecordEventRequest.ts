/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_security_analytics_router__RecordEventRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Cloud event source
     */
    event_source?: string;
    /**
     * Event type
     */
    event_type?: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * Cloud account ID
     */
    account_id?: string;
    /**
     * Cloud region
     */
    region?: string;
    /**
     * Resource type
     */
    resource_type?: string;
    /**
     * Resource ID
     */
    resource_id?: string;
    /**
     * Actor (user/role/service)
     */
    actor?: string;
    /**
     * Risk score 0-100
     */
    risk_score?: number;
    /**
     * Event details / raw payload
     */
    details?: string;
    /**
     * ISO-8601 event timestamp
     */
    event_at?: (string | null);
};

