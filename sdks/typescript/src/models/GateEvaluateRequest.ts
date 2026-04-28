/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { PolicyThresholds } from './PolicyThresholds';
/**
 * Evaluate findings against a specific policy.
 */
export type GateEvaluateRequest = {
    findings: Array<Record<string, any>>;
    policy_id?: (string | null);
    thresholds?: (PolicyThresholds | null);
};

