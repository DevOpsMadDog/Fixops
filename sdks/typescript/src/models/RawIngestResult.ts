/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Response for POST /api/v1/connectors/ingest/raw.
 */
export type RawIngestResult = {
    /**
     * Unique ID for this raw ingest
     */
    ingest_id: string;
    /**
     * Scanner type (e.g. 'sarif', 'json')
     */
    scan_type: string;
    /**
     * Product/project name
     */
    product_name: string;
    /**
     * When ingest was processed
     */
    timestamp: string;
    /**
     * Number of findings parsed
     */
    parsed_findings_count: number;
    /**
     * Parsing errors
     */
    errors?: Array<string>;
    /**
     * DefectDojo import ID (if applicable)
     */
    defectdojo_import_id?: (string | null);
};

