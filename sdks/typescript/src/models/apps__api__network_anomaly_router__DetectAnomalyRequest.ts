/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_anomaly_router__DetectAnomalyRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Network segment name
     */
    segment: string;
    /**
     * Protocol
     */
    protocol?: string;
    /**
     * Traffic direction
     */
    direction?: string;
    /**
     * Observed bytes per minute
     */
    bytes_per_min?: number;
    /**
     * Observed packets per minute
     */
    packets_per_min?: number;
};

