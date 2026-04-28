/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordDatapointRequest = {
    /**
     * Name of the security metric
     */
    metric_name: string;
    /**
     * vulnerability | compliance | identity | network | endpoint | cloud | data | awareness
     */
    metric_category: string;
    /**
     * Metric value
     */
    value: number;
    /**
     * score | percentage | count | days | hours
     */
    unit?: string;
    /**
     * Source system or tool
     */
    source?: string;
};

