/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__executive_reports__ReportType } from './core__executive_reports__ReportType';
import type { ReportFrequency } from './ReportFrequency';
/**
 * A scheduled report definition.
 */
export type ReportSchedule = {
    id?: string;
    report_type: core__executive_reports__ReportType;
    frequency: ReportFrequency;
    recipients?: Array<string>;
    next_run: string;
    enabled?: boolean;
    org_id?: string;
};

