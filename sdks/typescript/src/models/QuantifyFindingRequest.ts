/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request body for auto-quantifying a finding.
 */
export type QuantifyFindingRequest = {
    id?: (string | null);
    title?: (string | null);
    severity?: string;
    asset_type?: (string | null);
    asset_value_usd?: (number | null);
    description?: (string | null);
};

