/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest a Falcon Detection.Created dump.
 *
 * Exactly one of ``events`` (a list of detection dicts) or ``json_text``
 * (raw JSON / NDJSON string) must be supplied. ``org_id`` selects the
 * target ALDECI tenant for isolation.
 */
export type FalconIngestRequest = {
    org_id?: string;
    /**
     * List of Falcon Detection.Created event dicts.
     */
    events?: null;
    /**
     * Raw JSON string (array, single object, or NDJSON).
     */
    json_text?: (string | null);
    /**
     * Optional cap on number of events to process.
     */
    max_events?: (number | null);
};

