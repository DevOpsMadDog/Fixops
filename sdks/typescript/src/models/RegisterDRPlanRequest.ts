/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RegisterDRPlanRequest = {
    /**
     * DR plan name
     */
    name: string;
    /**
     * System this plan covers
     */
    system_name: string;
    /**
     * Recovery priority (1 = highest)
     */
    priority_order?: number;
    runbook_steps?: Array<Record<string, any>>;
    responsible_parties?: Array<string>;
    communication_plan?: Record<string, any>;
    rto_minutes?: number;
    rpo_minutes?: number;
    version?: string;
    approved_by?: (string | null);
    next_review_at?: (string | null);
    tags?: Array<string>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

