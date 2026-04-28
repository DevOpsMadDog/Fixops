/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to queue a notification.
 */
export type QueueNotificationRequest = {
    entity_type: string;
    entity_id: string;
    notification_type: string;
    title: string;
    message: string;
    recipients: Array<string>;
    priority?: string;
    metadata?: (Record<string, any> | null);
};

