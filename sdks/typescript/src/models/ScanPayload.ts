/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * POST /scan — scan content or a virtual source for sensitive data.
 */
export type ScanPayload = {
    content?: (string | null);
    source_type?: string;
    source_path?: (string | null);
    column_names?: (Array<string> | null);
    deep_scan?: boolean;
};

