/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorMetricsEntry } from './ConnectorMetricsEntry';
/**
 * Response for GET /api/v1/connectors/metrics.
 */
export type ConnectorMetricsResponse = {
    /**
     * When metrics were computed
     */
    timestamp: string;
    /**
     * Per-connector metrics
     */
    metrics: Array<ConnectorMetricsEntry>;
    /**
     * Total pulls across all connectors
     */
    total_pulls_24h: number;
    /**
     * Total findings ingested
     */
    total_findings_ingested_24h: number;
    /**
     * Overall error rate
     */
    overall_error_rate: number;
};

