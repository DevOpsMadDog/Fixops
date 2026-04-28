/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { LogFormat } from './LogFormat';
/**
 * Single log-line ingestion request.
 */
export type apps__api__audit_analytics_router__IngestRequest = {
    /**
     * Raw log line to ingest
     */
    raw: string;
    /**
     * Wire format of the log line
     */
    format?: LogFormat;
    /**
     * Override org_id (defaults to authenticated org)
     */
    org_id?: (string | null);
};

