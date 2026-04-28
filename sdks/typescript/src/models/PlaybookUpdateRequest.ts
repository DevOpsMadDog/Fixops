/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for updating a playbook.
 */
export type PlaybookUpdateRequest = {
    name?: (string | null);
    description?: (string | null);
    trigger_conditions?: (Record<string, any> | null);
    steps?: null;
    status?: (string | null);
    tags?: (Array<string> | null);
};

