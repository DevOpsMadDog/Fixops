/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__cloud_security_analytics_router__RecordAnomalyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Anomaly type
     */
    anomaly_type?: string;
    /**
     * Severity: critical/high/medium/low
     */
    severity?: string;
    /**
     * Cloud account ID
     */
    account_id?: string;
    /**
     * Confidence 0-100
     */
    confidence_score?: number;
    /**
     * Affected resource IDs
     */
    affected_resources?: Array<string>;
    /**
     * Anomaly status
     */
    status?: string;
    /**
     * ISO-8601 detection timestamp
     */
    detected_at?: (string | null);
};

