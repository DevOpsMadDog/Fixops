/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MaintenanceIssueResponse } from './MaintenanceIssueResponse';
/**
 * Full maintenance sweep report.
 */
export type MaintenanceReportResponse = {
    checked_at: string;
    cores_checked: Array<number>;
    issues: Array<MaintenanceIssueResponse>;
    stats: Record<string, number>;
    duration_ms: number;
    org_id: string;
    issue_count: number;
    critical_count: number;
    high_count: number;
};

