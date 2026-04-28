/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__ot_security_router__RecordAnomalyRequest = {
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Target asset ID
     */
    asset_id: string;
    /**
     * Type of anomaly
     */
    anomaly_type: string;
    /**
     * Severity: low/medium/high/critical
     */
    severity: string;
    /**
     * Anomaly description
     */
    description?: string;
};

