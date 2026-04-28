/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GateCheckDetail } from './GateCheckDetail';
/**
 * Gate evaluation response — the CI system consumes this.
 */
export type GateCheckResponse = {
    /**
     * Unique evaluation ID
     */
    gate_id: string;
    /**
     * Binary pass/fail — the CI exit code
     */
    passed: boolean;
    /**
     * PASS | FAIL | WARN
     */
    verdict: string;
    /**
     * Human-readable summary
     */
    reason: string;
    repository: string;
    commit_sha: string;
    branch: string;
    pull_request?: (number | null);
    /**
     * Total findings evaluated
     */
    findings_count?: number;
    policy_violations?: Array<Record<string, any>>;
    checks?: Array<GateCheckDetail>;
    checks_passed?: number;
    checks_failed?: number;
    checks_warned?: number;
    checks_skipped?: number;
    /**
     * ISO 8601 timestamp
     */
    evaluated_at: string;
    /**
     * Evaluation duration in milliseconds
     */
    evaluation_ms?: number;
};

