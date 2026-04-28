/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__FindingInput } from './apps__api__pr_gate_router__FindingInput';
import type { GatingPolicy } from './GatingPolicy';
/**
 * Request to evaluate findings against gating policy.
 */
export type apps__api__pr_gate_router__EvaluateRequest = {
    /**
     * Findings to evaluate
     */
    findings: Array<apps__api__pr_gate_router__FindingInput>;
    /**
     * Override policy (uses org default if not provided)
     */
    policy?: (GatingPolicy | null);
    /**
     * Commit SHA for tracking
     */
    commit_sha?: (string | null);
    /**
     * Branch name
     */
    branch?: (string | null);
    /**
     * Repository identifier
     */
    repository?: (string | null);
};

