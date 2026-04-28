/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /residency/register — register a dataset for residency tracking.
 */
export type ResidencyPayload = {
    dataset_name: string;
    data_categories: Array<string>;
    storage_region: string;
    approved_regions?: (Array<string> | null);
};

