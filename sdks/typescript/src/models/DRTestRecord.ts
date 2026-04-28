/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DRTestResult } from './DRTestResult';
import type { RemediationStatus } from './RemediationStatus';
/**
 * Record of a DR test exercise.
 */
export type DRTestRecord = {
    id?: string;
    dr_plan_id: string;
    system_name: string;
    test_date: string;
    result?: DRTestResult;
    tested_by: string;
    actual_rto_minutes?: (number | null);
    actual_rpo_minutes?: (number | null);
    gaps_found?: Array<string>;
    remediation_status?: RemediationStatus;
    remediation_notes?: (string | null);
    next_test_due?: (string | null);
    evidence_links?: Array<string>;
    org_id?: string;
    created_at?: string;
    updated_at?: string;
};

