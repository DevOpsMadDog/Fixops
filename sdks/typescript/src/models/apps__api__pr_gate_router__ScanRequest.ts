/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GatingPolicy } from './GatingPolicy';
/**
 * One-shot: scan repository → evaluate → report to PR.
 */
export type apps__api__pr_gate_router__ScanRequest = {
    /**
     * Repository owner
     */
    owner: string;
    /**
     * Repository name
     */
    repo: string;
    /**
     * Commit SHA
     */
    head_sha: string;
    /**
     * PR number
     */
    pr_number?: (number | null);
    /**
     * Branch to scan
     */
    branch?: string;
    /**
     * Scan types to run (sast, secrets, sca, iac)
     */
    scan_types?: Array<string>;
    /**
     * Override policy
     */
    policy?: (GatingPolicy | null);
    /**
     * Check run name
     */
    check_name?: string;
};

