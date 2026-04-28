/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to create correlation link between clusters.
 */
export type CreateCorrelationLinkRequest = {
    source_cluster_id: string;
    target_cluster_id: string;
    link_type: string;
    confidence: number;
    reason?: (string | null);
};

