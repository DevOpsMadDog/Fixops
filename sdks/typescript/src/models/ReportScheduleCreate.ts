/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__report_models__ReportType } from './core__report_models__ReportType';
import type { ReportFormat } from './ReportFormat';
/**
 * Request model for scheduling a report.
 */
export type ReportScheduleCreate = {
    report_type: core__report_models__ReportType;
    format?: ReportFormat;
    /**
     * Cron expression for schedule
     */
    schedule_cron: string;
    parameters?: Record<string, any>;
};

