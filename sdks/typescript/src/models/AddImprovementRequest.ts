/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type AddImprovementRequest = {
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * Name of the improvement initiative
     */
    improvement_name: string;
    /**
     * Priority: critical/high/medium/low
     */
    priority?: string;
    /**
     * Target maturity level
     */
    target_level?: number;
    /**
     * Estimated effort in days
     */
    effort_days?: number;
    /**
     * ISO-8601 due date
     */
    due_date?: string;
};

