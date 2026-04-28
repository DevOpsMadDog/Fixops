/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response body for the /webhook endpoint.
 */
export type WebhookResponse = {
    received?: boolean;
    commit_sha?: (string | null);
    analyses_count?: number;
    highest_risk?: string;
};

