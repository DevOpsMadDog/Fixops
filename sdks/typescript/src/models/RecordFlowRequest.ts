/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordFlowRequest = {
    /**
     * Source IP address
     */
    src_ip: string;
    /**
     * Destination IP address
     */
    dst_ip: string;
    /**
     * Source port
     */
    src_port: number;
    /**
     * Destination port
     */
    dst_port: number;
    /**
     * Protocol: tcp or udp
     */
    protocol?: string;
    /**
     * Bytes from source to destination
     */
    bytes_sent?: number;
    /**
     * Bytes from destination to source
     */
    bytes_recv?: number;
    packet_count?: number;
    duration_ms?: number;
    org_id?: string;
};

