/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Metrics for a single connector.
 */
export type ConnectorMetricsEntry = {
    /**
     * Connector name
     */
    name: string;
    /**
     * Successful pulls in last 24h
     */
    pull_count_24h: number;
    /**
     * Successful pulls in last 7d
     */
    pull_count_7d: number;
    /**
     * Errors in last 24h
     */
    error_count_24h: number;
    /**
     * Errors in last 7d
     */
    error_count_7d: number;
    /**
     * Error rate % (0.0-1.0)
     */
    error_rate_24h: number;
    /**
     * Findings ingested in last 24h
     */
    findings_ingested_24h: number;
    /**
     * Findings ingested in last 7d
     */
    findings_ingested_7d: number;
    /**
     * Last successful pull
     */
    last_pull_time?: (string | null);
    /**
     * Average pull duration
     */
    avg_pull_duration_seconds?: (number | null);
};

