/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__anomaly_ml_router__RecordEventRequest = {
    /**
     * User or service ID
     */
    entity_id: string;
    /**
     * Metric name, e.g. 'login_count'
     */
    metric_name: string;
    /**
     * Numeric metric value
     */
    value: number;
    /**
     * 'user' or 'service'
     */
    entity_type?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

