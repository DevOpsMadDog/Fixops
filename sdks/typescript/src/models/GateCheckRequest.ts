/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyThresholds } from './PolicyThresholds';
/**
 * Primary gate check request — accepts multiple input formats.
 */
export type GateCheckRequest = {
    /**
     * Repository identifier (owner/repo)
     */
    repository: string;
    /**
     * Commit SHA being evaluated
     */
    commit_sha?: string;
    /**
     * Branch name
     */
    branch?: string;
    /**
     * PR number (if applicable)
     */
    pull_request?: (number | null);
    /**
     * SARIF v2.1.0 scan results
     */
    sarif?: (Record<string, any> | null);
    /**
     * Pre-parsed findings list
     */
    findings?: null;
    /**
     * CycloneDX or SPDX SBOM
     */
    sbom?: (Record<string, any> | null);
    /**
     * Unified diff content for material change analysis
     */
    diff?: (string | null);
    /**
     * Named policy ID to evaluate against
     */
    policy_id?: (string | null);
    /**
     * Inline threshold overrides
     */
    thresholds?: (PolicyThresholds | null);
};

