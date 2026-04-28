/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { apps__api__pr_gate_router__FindingInput } from './apps__api__pr_gate_router__FindingInput';
import type { GatingPolicy } from './GatingPolicy';
/**
 * CI/CD gate evaluation request.
 */
export type CIGateRequest = {
    /**
     * Findings from CI pipeline
     */
    findings: Array<apps__api__pr_gate_router__FindingInput>;
    /**
     * Override policy
     */
    policy?: (GatingPolicy | null);
    /**
     * CI pipeline run ID
     */
    pipeline_id?: (string | null);
    /**
     * Commit SHA
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
    /**
     * Output format: json, sarif, text
     */
    format?: string;
};

