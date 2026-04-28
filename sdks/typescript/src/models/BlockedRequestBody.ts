/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type BlockedRequestBody = {
    rule_id?: string;
    source_ip?: string;
    uri?: string;
    method?: string;
    user_agent?: string;
    attack_type?: string;
    severity?: string;
    request_headers?: Record<string, string>;
    blocked_at?: (string | null);
};

