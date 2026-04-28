/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to update a work item in an ALM system.
 */
export type UpdateWorkItemRequest = {
    status?: (string | null);
    assignee?: (string | null);
    labels?: (Array<string> | null);
    comment?: (string | null);
    additional_fields?: (Record<string, any> | null);
};

