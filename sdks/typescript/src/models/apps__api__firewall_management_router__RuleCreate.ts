/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__firewall_management_router__RuleCreate = {
    rule_name?: string;
    src_zone?: string;
    dst_zone?: string;
    src_address?: string;
    dst_address?: string;
    service?: Array<string>;
    action?: string;
    expires_at?: (string | null);
};

