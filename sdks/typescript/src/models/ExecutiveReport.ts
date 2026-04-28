/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { core__executive_reports__ReportType } from './core__executive_reports__ReportType';
import type { ReportFrequency } from './ReportFrequency';
import type { ReportSection } from './ReportSection';
/**
 * A complete executive report.
 */
export type ExecutiveReport = {
    id?: string;
    title: string;
    type: core__executive_reports__ReportType;
    frequency?: ReportFrequency;
    org_id?: string;
    created_at?: string;
    period_start: string;
    period_end: string;
    sections?: Array<ReportSection>;
    metadata?: Record<string, any>;
    generated_by?: string;
};

