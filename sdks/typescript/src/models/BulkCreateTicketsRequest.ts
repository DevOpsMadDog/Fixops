/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for bulk ticket creation.
 */
export type BulkCreateTicketsRequest = {
    ids: Array<string>;
    integration_id: string;
    project_key?: (string | null);
    issue_type?: string;
    priority_mapping?: (Record<string, string> | null);
};

