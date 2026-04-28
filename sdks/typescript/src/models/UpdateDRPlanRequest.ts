/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type UpdateDRPlanRequest = {
    name?: (string | null);
    priority_order?: (number | null);
    runbook_steps?: null;
    responsible_parties?: (Array<string> | null);
    communication_plan?: (Record<string, any> | null);
    rto_minutes?: (number | null);
    rpo_minutes?: (number | null);
    version?: (string | null);
    approved_by?: (string | null);
    next_review_at?: (string | null);
    tags?: (Array<string> | null);
};

