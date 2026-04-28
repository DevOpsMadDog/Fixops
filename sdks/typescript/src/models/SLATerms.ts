/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Service Level Agreement terms.
 */
export type SLATerms = {
    /**
     * Uptime SLA %
     */
    uptime_percent?: number;
    /**
     * Hours to acknowledge incident
     */
    incident_response_hours?: number;
    /**
     * Hours to notify of breach
     */
    breach_notification_hours?: number;
    /**
     * Days to return data on termination
     */
    data_return_days?: number;
    /**
     * SLA review frequency in months
     */
    review_frequency_months?: number;
};

