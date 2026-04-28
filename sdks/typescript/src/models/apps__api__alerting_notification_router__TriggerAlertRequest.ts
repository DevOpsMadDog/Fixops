/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__alerting_notification_router__TriggerAlertRequest = {
    /**
     * Short alert title
     */
    title: string;
    /**
     * Detailed alert message
     */
    message: string;
    /**
     * Originating policy ID
     */
    policy_id?: (string | null);
    /**
     * Engine that raised the alert
     */
    source_engine?: (string | null);
    /**
     * Source record ID
     */
    source_id?: (string | null);
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Additional key-value context
     */
    context?: (Record<string, any> | null);
};

