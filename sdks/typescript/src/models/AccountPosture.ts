/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__cspm_engine__CloudProvider } from './core__cspm_engine__CloudProvider';
export type AccountPosture = {
    account_id: string;
    provider: core__cspm_engine__CloudProvider;
    org_id: string;
    total_resources: number;
    total_findings: number;
    critical_findings: number;
    high_findings: number;
    medium_findings: number;
    low_findings: number;
    risk_score: number;
    compliance_scores?: Record<string, number>;
    last_scanned?: string;
};

