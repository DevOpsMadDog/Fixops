/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Metadata about the ingest request.
 */
export type ConnectorIngestMeta = {
    /**
     * Connector version
     */
    connector_version: string;
    /**
     * When findings were pulled from source
     */
    pull_timestamp: string;
    /**
     * Current page in paginated pull
     */
    page_number?: (number | null);
    /**
     * Findings per page
     */
    page_size?: (number | null);
    /**
     * Total pages in pull
     */
    total_pages?: (number | null);
    /**
     * Source API endpoint queried
     */
    api_endpoint?: (string | null);
};

