/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { FindingRequest } from './FindingRequest';
/**
 * Bidirectional sync request.
 */
export type apps__api__github_issues_router__SyncRequest = {
    /**
     * Findings to push to GitHub. Leave empty for GitHub→ALDECI pull only.
     */
    findings?: Array<FindingRequest>;
    /**
     * 'to_github' | 'from_github' | 'both'
     */
    direction?: string;
    /**
     * Log without making API calls
     */
    dry_run?: boolean;
};

