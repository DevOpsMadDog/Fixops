/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * GitHub webhook payload (push / pull_request events).
 */
export type GitHubWebhookPayload = {
    action?: (string | null);
    ref?: (string | null);
    before?: (string | null);
    after?: (string | null);
    repository?: (Record<string, any> | null);
    sender?: (Record<string, any> | null);
    commits?: null;
    pull_request?: (Record<string, any> | null);
    head_commit?: (Record<string, any> | null);
};

