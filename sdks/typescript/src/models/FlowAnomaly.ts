/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__network_security__Severity } from './core__network_security__Severity';
import type { FlowAnomalyType } from './FlowAnomalyType';
export type FlowAnomaly = {
    id?: string;
    org_id: string;
    anomaly_type: FlowAnomalyType;
    src_ip: string;
    dst_ip: string;
    severity: core__network_security__Severity;
    description: string;
    flow_ids?: Array<string>;
    detected_at?: string;
};

