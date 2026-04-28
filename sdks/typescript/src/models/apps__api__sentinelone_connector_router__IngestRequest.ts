/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest a SentinelOne /threats dump.
 *
 * ``payload`` accepts:
 * - the API canonical wrapper ``{"data": [Threat, ...], "pagination": {...}}``
 * - a list of Threat dicts
 * - a single Threat dict
 */
export type apps__api__sentinelone_connector_router__IngestRequest = {
    org_id?: string;
    /**
     * SentinelOne /threats response: dict with 'data' list, list, or single Threat
     */
    payload: Record<string, any>;
    scan_id?: (string | null);
};

