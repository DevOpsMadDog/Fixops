/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__webhook_events_router__RegisterWebhookRequest = {
    /**
     * n8n webhook URL (HTTPS recommended)
     */
    url: string;
    /**
     * Event types to subscribe to
     */
    event_types: Array<string>;
    /**
     * HMAC secret (auto-generated if omitted)
     */
    secret?: (string | null);
    description?: (string | null);
};

