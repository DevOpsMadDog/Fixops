/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__breach_detection_router__RecordEventRequest = {
    org_id?: string;
    /**
     * ID of the triggering rule
     */
    rule_id: string;
    /**
     * low/medium/high/critical
     */
    severity: string;
    /**
     * Host, user, or IP that triggered the event
     */
    entity: string;
    /**
     * List of indicators
     */
    indicators?: Array<string>;
    /**
     * Number of matched occurrences
     */
    matched_count?: number;
    status?: string;
};

