/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
import type { ConnectorIngestMeta } from './ConnectorIngestMeta';
import type { NormalizedFinding } from './NormalizedFinding';
/**
 * Main request body for POST /api/v1/connectors/ingest.
 */
export type IngestPayload = {
    /**
     * Connector name (e.g., 'github', 'jira')
     */
    source: string;
    /**
     * List of normalized findings
     */
    findings: Array<NormalizedFinding>;
    /**
     * Ingest metadata
     */
    metadata: ConnectorIngestMeta;
};

