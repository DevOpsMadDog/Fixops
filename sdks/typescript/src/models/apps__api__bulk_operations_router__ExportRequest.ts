/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
export type apps__api__bulk_operations_router__ExportRequest = {
    org_id: string;
    /**
     * Export format: csv, json, sarif
     */
    format?: string;
    /**
     * Filter findings by field values
     */
    filters?: Record<string, any>;
};

