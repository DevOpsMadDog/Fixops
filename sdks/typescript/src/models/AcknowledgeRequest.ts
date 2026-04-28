/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Body for acknowledging a user's alerts.
 */
export type AcknowledgeRequest = {
    /**
     * Reviewer identifier (email / username)
     */
    reviewer: string;
    /**
     * Organisation ID
     */
    org_id?: string;
};

