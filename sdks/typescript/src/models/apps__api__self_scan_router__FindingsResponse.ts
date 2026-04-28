/* generated using openapi-typescript-codegen -- do not edit */
/* istanbul ignore file */
/* tslint:disable */
/* eslint-disable */
/**
 * Paginated findings response.
 */
export type apps__api__self_scan_router__FindingsResponse = {
    total: number;
    category_filter?: (string | null);
    severity_filter?: (string | null);
    findings: Array<Record<string, any>>;
};

