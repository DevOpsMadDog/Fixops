/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ReachabilityLevel } from './ReachabilityLevel';
/**
 * Reachability analysis for a finding.
 */
export type ReachabilityResult = {
    finding_id: string;
    level: ReachabilityLevel;
    /**
     * Call graph path to vuln code
     */
    call_path?: Array<string>;
    evidence?: string;
    analyzer?: string;
    analyzed_at?: string;
};

