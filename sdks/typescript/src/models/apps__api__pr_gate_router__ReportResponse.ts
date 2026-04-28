/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { GateVerdict } from './GateVerdict';
/**
 * Result of posting findings to GitHub.
 */
export type apps__api__pr_gate_router__ReportResponse = {
    verdict: GateVerdict;
    check_run_id?: (number | null);
    check_run_url?: (string | null);
    comment_posted?: boolean;
    summary?: string;
    evaluation_id?: string;
};

