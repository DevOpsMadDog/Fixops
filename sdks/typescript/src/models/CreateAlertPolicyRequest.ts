/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateAlertPolicyRequest = {
    /**
     * Human-readable policy name
     */
    name: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * threshold | anomaly | pattern | schedule
     */
    condition_type?: string;
    /**
     * Delivery channels: email, slack, pagerduty, webhook
     */
    channels?: Array<string>;
    /**
     * Whether the policy is active
     */
    enabled?: boolean;
};

