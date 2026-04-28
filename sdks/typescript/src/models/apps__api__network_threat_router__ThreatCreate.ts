/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__network_threat_router__ThreatCreate = {
    threat_name: string;
    threat_type: string;
    source_ip: string;
    dest_ip: string;
    dest_port?: number;
    protocol?: string;
    severity?: string;
    confidence?: number;
};

