/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KPICategory } from './KPICategory';
import type { KPITrend } from './KPITrend';
/**
 * A security KPI data point.
 */
export type KPI = {
    id?: string;
    /**
     * Machine-readable KPI name (e.g. mttd_minutes)
     */
    name: string;
    /**
     * Current KPI value
     */
    value: number;
    /**
     * Target value for this KPI
     */
    target?: (number | null);
    /**
     * Unit of measure (minutes, %, count, etc.)
     */
    unit?: string;
    /**
     * Direction of change vs. prior period
     */
    trend?: KPITrend;
    /**
     * KPI category
     */
    category: KPICategory;
    /**
     * Reporting period (e.g. 2026-04, daily, weekly)
     */
    period?: string;
    /**
     * Organisation identifier
     */
    org_id?: string;
    recorded_at?: string;
    metadata?: Record<string, any>;
};

