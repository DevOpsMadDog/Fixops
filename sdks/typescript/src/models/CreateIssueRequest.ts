/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingRequest } from './FindingRequest';
/**
 * Create a GitHub issue from a finding.
 */
export type CreateIssueRequest = {
    finding: FindingRequest;
    /**
     * GitHub username to assign
     */
    assignee?: (string | null);
    /**
     * Additional labels
     */
    extra_labels?: Array<string>;
};

