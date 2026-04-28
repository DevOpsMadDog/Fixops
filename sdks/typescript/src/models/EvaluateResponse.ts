/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GateVerdict } from './GateVerdict';
import type { GatingPolicy } from './GatingPolicy';
/**
 * Result of gate evaluation.
 */
export type EvaluateResponse = {
    verdict: GateVerdict;
    /**
     * 0=pass, 1=fail, 2=warn
     */
    exit_code: number;
    summary: string;
    findings_total: number;
    findings_by_severity: Record<string, number>;
    blocking_findings: Array<Record<string, any>>;
    warning_findings: Array<Record<string, any>>;
    policy_applied: GatingPolicy;
    evaluation_id: string;
    evaluated_at: string;
};

