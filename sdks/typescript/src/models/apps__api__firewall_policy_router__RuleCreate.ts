/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__firewall_policy_router__RuleCreate = {
    name: string;
    action: string;
    src_zones?: Array<string>;
    dst_zones?: Array<string>;
    src_ips?: Array<string>;
    dst_ips?: Array<string>;
    ports?: Array<string>;
    protocol?: string;
    enabled?: boolean;
    order_num?: number;
    hit_count?: number;
    last_hit_at?: (string | null);
};

