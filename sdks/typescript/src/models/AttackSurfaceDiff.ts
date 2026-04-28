/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ServiceInfo } from './ServiceInfo';
export type AttackSurfaceDiff = {
    id?: string;
    snapshot_old_id: string;
    snapshot_new_id: string;
    target: string;
    computed_at?: string;
    added_ports?: Array<number>;
    removed_ports?: Array<number>;
    added_services?: Array<ServiceInfo>;
    removed_services?: Array<ServiceInfo>;
    added_endpoints?: Array<string>;
    removed_endpoints?: Array<string>;
    new_secrets?: Array<string>;
    closed_secrets?: Array<string>;
    score_delta?: number;
    risk_increased?: boolean;
    change_count?: number;
};

