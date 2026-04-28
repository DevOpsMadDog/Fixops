/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest a raw JSON-encoded dump (string body).
 *
 * Useful for clients that already have the raw API response and don't want
 * to re-parse it client-side.
 */
export type IngestRawRequest = {
    org_id?: string;
    raw_json: string;
    scan_id?: (string | null);
};

