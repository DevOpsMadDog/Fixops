/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_monitoring_router__TrafficSampleRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Bytes received
     */
    bytes_in?: number;
    /**
     * Bytes transmitted
     */
    bytes_out?: number;
    /**
     * Packets received
     */
    packets_in?: number;
    /**
     * Packets transmitted
     */
    packets_out?: number;
    /**
     * ISO-8601 sample timestamp
     */
    timestamp?: (string | null);
};

