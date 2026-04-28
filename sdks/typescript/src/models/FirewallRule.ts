/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type FirewallRule = {
    id?: string;
    org_id: string;
    rule_name: string;
    src: string;
    dst: string;
    port: string;
    protocol: string;
    action: string;
    bidirectional?: boolean;
    expiry?: (string | null);
    hit_count?: number;
    created_at?: string;
    metadata?: Record<string, any>;
};

