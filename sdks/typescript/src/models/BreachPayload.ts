/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /breach-impact — assess regulatory impact of a breach.
 */
export type BreachPayload = {
    breach_id?: (string | null);
    affected_systems?: Array<string>;
    estimated_records: number;
    data_categories: Array<string>;
    storage_regions?: (Array<string> | null);
    discovery_date?: (string | null);
};

