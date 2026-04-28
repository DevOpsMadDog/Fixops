/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * A single quality issue detected in TrustGraph.
 */
export type QualityIssueResponse = {
    issue_id: string;
    type: string;
    severity: string;
    description: string;
    entity_count: number;
    auto_fixable: boolean;
    example_ids: Array<string>;
    detected_at: string;
};

