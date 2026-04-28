/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__security_metrics__ReportType } from './core__security_metrics__ReportType';
/**
 * Request body for report generation.
 */
export type apps__api__security_metrics_router__ReportRequest = {
    report_type: core__security_metrics__ReportType;
    industry?: string;
    extra_context?: (Record<string, any> | null);
};

