/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__uba_router__CreateAlertRequest = {
    org_id: string;
    user_id: string;
    /**
     * Type/category of the alert
     */
    alert_type: string;
    /**
     * low | medium | high | critical
     */
    severity?: string;
    /**
     * Human-readable alert description
     */
    description?: string;
};

