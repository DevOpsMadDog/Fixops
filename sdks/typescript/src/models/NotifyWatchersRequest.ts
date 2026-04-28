/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to notify all watchers of an entity.
 */
export type NotifyWatchersRequest = {
    entity_type: string;
    entity_id: string;
    notification_type: string;
    title: string;
    message: string;
    priority?: string;
    metadata?: (Record<string, any> | null);
    exclude_users?: (Array<string> | null);
};

