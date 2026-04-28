/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__security_registry_router__ReviewCreate = {
    /**
     * Name of the reviewer
     */
    reviewer: string;
    /**
     * approved | rejected | approved_with_changes | deferred
     */
    review_outcome: string;
    comments?: string;
    review_date?: (string | null);
    next_review_date?: (string | null);
};

