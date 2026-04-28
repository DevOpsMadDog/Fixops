/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * For ad-hoc alert notifications via the API.
 */
export type SlackAlertRequest = {
    /**
     * Alert title
     */
    title: string;
    /**
     * Alert details
     */
    message?: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Alert ID
     */
    alert_id?: (string | null);
    /**
     * Source engine name
     */
    source_engine?: (string | null);
    /**
     * Organisation ID
     */
    org_id?: (string | null);
};

