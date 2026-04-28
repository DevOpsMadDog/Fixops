/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create a remediation task.
 */
export type apps__api__remediation_router__CreateTaskRequest = {
    cluster_id: string;
    org_id: string;
    app_id: string;
    title: string;
    severity: string;
    description?: (string | null);
    assignee?: (string | null);
    assignee_email?: (string | null);
    metadata?: (Record<string, any> | null);
};

