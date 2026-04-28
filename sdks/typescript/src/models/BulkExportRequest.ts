/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Request model for bulk export.
 */
export type BulkExportRequest = {
    ids: Array<string>;
    format?: string;
    include_fields?: (Array<string> | null);
    org_id: string;
};

