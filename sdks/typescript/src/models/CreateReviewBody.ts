/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type CreateReviewBody = {
    /**
     * Name of this architecture review
     */
    review_name: string;
    /**
     * System or service being reviewed
     */
    system_name: string;
    /**
     * full | partial | threat-model | compliance | vendor
     */
    review_type?: string;
    /**
     * Reviewer name or ID
     */
    reviewer?: string;
};

