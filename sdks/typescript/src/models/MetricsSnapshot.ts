/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { Metric } from './Metric';
/**
 * Aggregate snapshot of all security metrics for an org.
 */
export type MetricsSnapshot = {
    id?: string;
    /**
     * Organisation identifier
     */
    org_id: string;
    /**
     * ISO-8601 UTC timestamp
     */
    timestamp?: string;
    metrics?: Array<Metric>;
    summary?: Record<string, any>;
};

