/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__executive_reports__ReportType } from './core__executive_reports__ReportType';
import type { ReportFrequency } from './ReportFrequency';
/**
 * Request body for schedule creation.
 */
export type apps__api__executive_report_router__CreateScheduleRequest = {
    /**
     * Report type to schedule
     */
    report_type: core__executive_reports__ReportType;
    /**
     * Generation frequency
     */
    frequency: ReportFrequency;
    /**
     * Email addresses or identifiers for delivery
     */
    recipients?: Array<string>;
    /**
     * Organisation identifier
     */
    org_id?: string;
};

