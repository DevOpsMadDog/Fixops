/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request to export threat intelligence for air-gapped sharing.
 */
export type ExportThreatIntelRequest = {
    /**
     * Absolute output path for the exported bundle
     */
    output_path: string;
    /**
     * Override classification level for this export
     */
    classification?: (string | null);
};

