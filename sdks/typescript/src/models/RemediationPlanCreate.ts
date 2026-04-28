/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RemediationPlanCreate = {
    assessment_id: string;
    control_id: string;
    /**
     * p1/p2/p3/p4
     */
    priority?: string;
    assigned_team?: string;
    /**
     * low/medium/high
     */
    estimated_effort?: string;
    target_date?: string;
    notes?: string;
};

