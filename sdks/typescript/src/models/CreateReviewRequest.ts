/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for creating an access review campaign.
 */
export type CreateReviewRequest = {
    /**
     * Human-readable review campaign name
     */
    name: string;
    /**
     * Scope description, e.g. 'Q2 privileged access review'
     */
    scope?: string;
    /**
     * User ID of the reviewer
     */
    reviewer_id: string;
    /**
     * ISO 8601 deadline, e.g. '2026-05-01T00:00:00Z'
     */
    deadline: string;
    /**
     * Which accounts to include: 'privileged', 'service_accounts', or 'all'
     */
    access_type?: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

