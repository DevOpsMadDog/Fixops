/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__webhook_notifications_router__RegisterWebhookRequest = {
    /**
     * Organization identifier
     */
    org_id: string;
    /**
     * Target HTTPS URL
     */
    url: string;
    /**
     * Event types to subscribe to
     */
    events: Array<string>;
    description?: (string | null);
};

