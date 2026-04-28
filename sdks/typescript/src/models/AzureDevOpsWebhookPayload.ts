/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Azure DevOps webhook payload for work item events.
 */
export type AzureDevOpsWebhookPayload = {
    subscriptionId?: (string | null);
    notificationId?: (number | null);
    eventType: string;
    resource?: (Record<string, any> | null);
    resourceVersion?: (string | null);
    resourceContainers?: (Record<string, any> | null);
};

