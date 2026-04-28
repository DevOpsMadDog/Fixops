/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DRTestResult } from './DRTestResult';
import type { RemediationStatus } from './RemediationStatus';
export type RecordDRTestRequest = {
    /**
     * DR plan that was tested
     */
    dr_plan_id: string;
    /**
     * System that was tested
     */
    system_name: string;
    /**
     * ISO-8601 date of the test
     */
    test_date: string;
    /**
     * Test outcome
     */
    result: DRTestResult;
    /**
     * Person or team who ran the test
     */
    tested_by: string;
    actual_rto_minutes?: (number | null);
    actual_rpo_minutes?: (number | null);
    gaps_found?: Array<string>;
    remediation_status?: RemediationStatus;
    remediation_notes?: (string | null);
    next_test_due?: (string | null);
    evidence_links?: Array<string>;
    /**
     * Organisation ID
     */
    org_id?: string;
};

