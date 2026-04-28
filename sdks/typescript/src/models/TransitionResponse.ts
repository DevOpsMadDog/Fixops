/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after a successful transition.
 */
export type TransitionResponse = {
    event_id: string;
    finding_id: string;
    from_stage: (string | null);
    to_stage: string;
    changed_by: string;
    reason: string;
    timestamp: string;
    org_id: string;
};

