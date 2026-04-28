/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create a work item in an ALM system.
 */
export type CreateWorkItemRequest = {
    cluster_id?: string;
    integration_type?: CreateWorkItemRequest.integration_type;
    title?: string;
    description?: (string | null);
    severity?: (string | null);
    labels?: (Array<string> | null);
    assignee?: (string | null);
    project_id?: (string | null);
    additional_fields?: (Record<string, any> | null);
};
export namespace CreateWorkItemRequest {
    export enum integration_type {
        GITLAB = 'gitlab',
        AZURE_DEVOPS = 'azure_devops',
        JIRA = 'jira',
        SERVICENOW = 'servicenow',
    }
}

