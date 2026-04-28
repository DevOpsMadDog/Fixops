/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordUtilizationRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Utilization percentage 0-100
     */
    utilization_pct?: number;
    /**
     * Traffic direction: inbound/outbound/both
     */
    direction?: string;
    /**
     * ISO-8601 timestamp
     */
    recorded_at?: (string | null);
};

