/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__executive_reports__ReportType } from './core__executive_reports__ReportType';
import type { ReportFrequency } from './ReportFrequency';
/**
 * Request body for report generation.
 */
export type apps__api__executive_report_router__GenerateReportRequest = {
    /**
     * Report type to generate
     */
    type: core__executive_reports__ReportType;
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Period start (ISO 8601). Defaults to 30 days ago.
     */
    period_start?: (string | null);
    /**
     * Period end (ISO 8601). Defaults to now.
     */
    period_end?: (string | null);
    /**
     * Report frequency label
     */
    frequency?: ReportFrequency;
};

