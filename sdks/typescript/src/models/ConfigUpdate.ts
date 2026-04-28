/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type ConfigUpdate = {
    mode?: (string | null);
    block_sqli?: (boolean | null);
    block_xss?: (boolean | null);
    block_cmdi?: (boolean | null);
    block_path_traversal?: (boolean | null);
    block_ssrf?: (boolean | null);
    block_prototype_pollution?: (boolean | null);
    block_deserialization?: (boolean | null);
    block_bots?: (boolean | null);
    block_zero_day_patterns?: (boolean | null);
    rate_limit_rpm?: (number | null);
    bot_score_threshold?: (number | null);
    ip_allowlist?: (Array<string> | null);
    ip_denylist?: (Array<string> | null);
};

