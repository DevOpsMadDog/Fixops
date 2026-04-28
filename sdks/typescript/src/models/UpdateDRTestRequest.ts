/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { DRTestResult } from './DRTestResult';
import type { RemediationStatus } from './RemediationStatus';
export type UpdateDRTestRequest = {
    result?: (DRTestResult | null);
    actual_rto_minutes?: (number | null);
    actual_rpo_minutes?: (number | null);
    gaps_found?: (Array<string> | null);
    remediation_status?: (RemediationStatus | null);
    remediation_notes?: (string | null);
    next_test_due?: (string | null);
    evidence_links?: (Array<string> | null);
};

