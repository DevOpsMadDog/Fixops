/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Vendor record with computed risk score.
 */
export type VendorResponse = {
    id: string;
    name: string;
    service_category: string;
    data_access_level: string;
    is_core_operations: boolean;
    tier: (string | null);
    current_score: (number | null);
    contract_start: string;
    contract_end: string;
    description: string;
    created_at: string;
    updated_at: string;
};

