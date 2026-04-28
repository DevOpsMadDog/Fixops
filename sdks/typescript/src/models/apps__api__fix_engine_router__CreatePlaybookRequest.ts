/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__fix_engine_router__CreatePlaybookRequest = {
    name: string;
    type: string;
    description?: string;
    steps: Array<Record<string, any>>;
    requires_approval?: boolean;
    auto_rollback?: boolean;
    target_finding_id?: (string | null);
    org_id?: string;
    created_by?: string;
};

