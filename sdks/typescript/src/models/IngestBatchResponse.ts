/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response after batch ingestion.
 */
export type IngestBatchResponse = {
    ingested: number;
    anomalies_detected: number;
    anomaly_ids?: Array<string>;
};

