/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { KPICategory } from './KPICategory';
import type { KPIHealth } from './KPIHealth';
import type { KPITrend } from './KPITrend';
/**
 * RAG health status for a single KPI.
 */
export type KPIHealthStatus = {
    name: string;
    value: number;
    target: (number | null);
    health: KPIHealth;
    trend: KPITrend;
    category: KPICategory;
    unit: string;
};

