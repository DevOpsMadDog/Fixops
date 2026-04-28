/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type RecordAccessReviewRequest = {
    org_id?: string;
    identity_id: string;
    reviewer?: string;
    review_type?: string;
    outcome?: string;
    findings?: Array<string>;
    reviewed_at?: (string | null);
};

