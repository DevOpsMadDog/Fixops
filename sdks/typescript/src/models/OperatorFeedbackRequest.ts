/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to record operator feedback for correlation corrections.
 */
export type OperatorFeedbackRequest = {
    cluster_id: string;
    /**
     * merge_allowed, merge_blocked, or split_cluster
     */
    feedback_type: OperatorFeedbackRequest.feedback_type;
    target_cluster_id?: (string | null);
    reason?: (string | null);
    operator_id?: (string | null);
};
export namespace OperatorFeedbackRequest {
    /**
     * merge_allowed, merge_blocked, or split_cluster
     */
    export enum feedback_type {
        MERGE_ALLOWED = 'merge_allowed',
        MERGE_BLOCKED = 'merge_blocked',
        SPLIT_CLUSTER = 'split_cluster',
    }
}

