/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Add a comment to a GitHub issue.
 */
export type UpdateIssueRequest = {
    /**
     * Finding identifier (used to look up issue number)
     */
    finding_id: string;
    /**
     * Markdown comment body
     */
    comment: string;
    /**
     * Override issue number if not linked
     */
    issue_number?: (number | null);
};

