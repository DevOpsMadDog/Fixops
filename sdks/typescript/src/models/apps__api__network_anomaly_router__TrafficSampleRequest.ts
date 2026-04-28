/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_anomaly_router__TrafficSampleRequest = {
    /**
     * Organisation ID
     */
    org_id?: string;
    /**
     * Network segment name
     */
    segment: string;
    /**
     * TCP/UDP/ICMP/HTTP/HTTPS/DNS/SMTP/FTP/SSH/other
     */
    protocol?: string;
    /**
     * inbound/outbound/lateral
     */
    direction?: string;
    /**
     * Bytes per minute
     */
    bytes_per_min?: number;
    /**
     * Packets per minute
     */
    packets_per_min?: number;
};

