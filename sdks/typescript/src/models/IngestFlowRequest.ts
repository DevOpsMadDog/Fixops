/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type IngestFlowRequest = {
    /**
     * Source IP address
     */
    src_ip?: string;
    /**
     * Destination IP address
     */
    dst_ip?: string;
    src_port?: number;
    dst_port?: number;
    /**
     * Protocol (TCP/UDP/ICMP/DNS/HTTP/HTTPS/SSH/RDP)
     */
    protocol?: string;
    bytes_sent?: number;
    bytes_recv?: number;
    duration_ms?: number;
    /**
     * internal/external/lateral/exfiltration_suspect/c2_suspect
     */
    flow_type?: string;
    mitre_technique?: string;
    observed_at?: (string | null);
};

