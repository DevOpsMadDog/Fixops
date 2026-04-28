/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LogFormat } from './LogFormat';
/**
 * Batch log ingestion request.
 */
export type IngestBatchRequest = {
    /**
     * List of raw log lines
     */
    lines: Array<string>;
    /**
     * Wire format shared by all lines
     */
    format?: LogFormat;
    /**
     * Run anomaly detection on the batch
     */
    run_anomaly_detection?: boolean;
    org_id?: (string | null);
};

