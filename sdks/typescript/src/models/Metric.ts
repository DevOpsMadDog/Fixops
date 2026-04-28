/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { MetricCategory } from './MetricCategory';
import type { MetricTrend } from './MetricTrend';
/**
 * A single named security metric.
 */
export type Metric = {
    /**
     * Metric identifier
     */
    name: string;
    /**
     * Numeric metric value
     */
    value: number;
    /**
     * Unit label (e.g. 'score', 'count', '%')
     */
    unit?: string;
    /**
     * Metric category
     */
    category: MetricCategory;
    /**
     * Trend direction
     */
    trend?: MetricTrend;
    /**
     * Percentage change vs previous period
     */
    change_pct?: number;
    /**
     * Period label
     */
    period?: string;
};

