/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type DatapointCreate = {
    /**
     * Type of telemetry metric
     */
    telemetry_type?: string;
    /**
     * siem/edr/ndr/firewall/ids/cloud/custom
     */
    source?: string;
    /**
     * Metric value
     */
    value?: number;
    /**
     * Unit of measurement
     */
    unit?: string;
    /**
     * Optional tags
     */
    tags?: Record<string, any>;
    /**
     * ISO 8601 collection timestamp
     */
    collected_at?: (string | null);
};

