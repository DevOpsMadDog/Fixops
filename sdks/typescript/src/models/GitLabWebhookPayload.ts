/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * GitLab webhook payload for issue events.
 */
export type GitLabWebhookPayload = {
    object_kind: string;
    event_type?: (string | null);
    object_attributes?: (Record<string, any> | null);
    project?: (Record<string, any> | null);
    user?: (Record<string, any> | null);
    labels?: null;
};

