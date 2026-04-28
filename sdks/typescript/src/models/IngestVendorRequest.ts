/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Ingest already-collected events from a third-party IdP.
 */
export type IngestVendorRequest = {
    /**
     * IdP vendor whose raw event format to parse
     */
    vendor: string;
    /**
     * Target realm / org_id for the events
     */
    realm: string;
    /**
     * Raw vendor events (max 1000)
     */
    events: Array<Record<string, any>>;
};

