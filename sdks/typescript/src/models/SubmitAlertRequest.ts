/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type SubmitAlertRequest = {
    /**
     * Unique alert identifier from source system
     */
    alert_id: string;
    /**
     * Source system name (e.g. SIEM, EDR)
     */
    alert_source: string;
    /**
     * critical | high | medium | low
     */
    severity?: string;
    /**
     * Raw indicator value to enrich
     */
    raw_indicator: string;
    /**
     * ip | domain | url | hash | email | user | process | registry
     */
    indicator_type?: string;
};

