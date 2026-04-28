/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__n8n_router__RegisterWebhookRequest = {
    /**
     * Human-readable webhook name
     */
    name: string;
    /**
     * Event type to listen for
     */
    event_type: string;
    /**
     * n8n webhook URL
     */
    webhook_url: string;
};

