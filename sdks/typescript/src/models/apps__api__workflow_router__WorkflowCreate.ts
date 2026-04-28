/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__workflow_router__WorkflowCreate = {
    name: string;
    description?: (string | null);
    trigger: string;
    conditions?: Array<Record<string, any>>;
    actions?: Array<Record<string, any>>;
    enabled?: boolean;
    created_by?: string;
    org_id?: string;
};

