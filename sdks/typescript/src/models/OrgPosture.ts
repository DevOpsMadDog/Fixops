/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { AccountPosture } from './AccountPosture';
export type OrgPosture = {
    org_id: string;
    overall_score: number;
    total_resources: number;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    accounts?: Array<AccountPosture>;
    compliance_scores?: Record<string, number>;
    scanned_at?: string;
};

