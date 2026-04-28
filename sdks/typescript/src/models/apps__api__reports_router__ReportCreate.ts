/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__report_models__ReportType } from './core__report_models__ReportType';
import type { ReportFormat } from './ReportFormat';
/**
 * Request model for creating a report.
 */
export type apps__api__reports_router__ReportCreate = {
    name?: string;
    report_type?: core__report_models__ReportType;
    format?: ReportFormat;
    parameters?: Record<string, any>;
    framework?: (string | null);
};

