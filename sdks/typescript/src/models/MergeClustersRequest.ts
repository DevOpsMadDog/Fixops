/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to merge multiple clusters into one.
 */
export type MergeClustersRequest = {
    source_cluster_ids: Array<string>;
    target_cluster_id: string;
    reason?: (string | null);
};

