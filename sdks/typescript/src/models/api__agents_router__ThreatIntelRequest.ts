/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request for threat intelligence.
 */
export type api__agents_router__ThreatIntelRequest = {
    cve_ids?: Array<string>;
    asset_ids?: Array<string>;
    include_dark_web?: boolean;
    include_zero_day?: boolean;
};

