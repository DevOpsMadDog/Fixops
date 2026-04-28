/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create pull request.
 */
export type CreatePRRequest = {
    finding_ids: Array<string>;
    repository: string;
    branch?: string;
    auto_merge?: boolean;
};

