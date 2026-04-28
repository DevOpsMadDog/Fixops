/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KPICategory } from './KPICategory';
/**
 * Request body for recording a KPI value.
 */
export type KPIRecordRequest = {
    /**
     * KPI name (e.g. mttd_minutes)
     */
    name: string;
    /**
     * Numeric KPI value
     */
    value: number;
    /**
     * KPI category
     */
    category: KPICategory;
    /**
     * Organisation identifier
     */
    org_id?: string;
    /**
     * Reporting period label (e.g. 2026-04)
     */
    period?: string;
    metadata?: Record<string, any>;
};

