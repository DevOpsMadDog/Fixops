/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Complete fourth-party risk map.
 */
export type FourthPartyMap = {
    direct_vendor_count?: number;
    fourth_party_count?: number;
    active_transitive_risks?: number;
    dependency_chains?: Array<Record<string, any>>;
    high_risk_fourth_parties?: Array<Record<string, any>>;
};

