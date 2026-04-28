/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Business continuity readiness score for an org.
 */
export type BCScore = {
    org_id: string;
    score?: number;
    grade?: string;
    backup_coverage_pct?: number;
    test_frequency_score?: number;
    rpo_compliance_pct?: number;
    rto_compliance_pct?: number;
    encryption_coverage_pct?: number;
    geo_redundancy_pct?: number;
    verification_pass_rate?: number;
    open_gaps?: number;
    systems_without_backup?: Array<string>;
    systems_without_dr_plan?: Array<string>;
    computed_at?: string;
};

