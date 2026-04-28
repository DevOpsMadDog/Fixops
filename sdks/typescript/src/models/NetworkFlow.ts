/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type NetworkFlow = {
    id?: string;
    org_id: string;
    src_ip: string;
    dst_ip: string;
    src_port: number;
    dst_port: number;
    protocol: string;
    bytes_sent?: number;
    bytes_recv?: number;
    packet_count?: number;
    duration_ms?: number;
    observed_at?: string;
};

