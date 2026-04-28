/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__FindingInput } from './apps__api__pr_gate_router__FindingInput';
import type { GatingPolicy } from './GatingPolicy';
/**
 * Request to post findings to a GitHub PR.
 */
export type apps__api__pr_gate_router__ReportRequest = {
    /**
     * Repository owner
     */
    owner: string;
    /**
     * Repository name
     */
    repo: string;
    /**
     * Commit SHA (head of the PR)
     */
    head_sha: string;
    /**
     * PR number (for comment posting)
     */
    pr_number?: (number | null);
    /**
     * Findings to report
     */
    findings: Array<apps__api__pr_gate_router__FindingInput>;
    /**
     * Override policy
     */
    policy?: (GatingPolicy | null);
    /**
     * Post summary comment on PR
     */
    post_comment?: boolean;
    /**
     * Create GitHub check run
     */
    create_check_run?: boolean;
    /**
     * Check run name
     */
    check_name?: string;
};

